import { authSigned, bitcoinOutpoint, demand, digest, halfAway, hex32, max, min, positive, u64 } from './common.mjs';
const COIN = 'SHZ/USD/COIN-ATTESTATION/V1';
const LIABILITY = 'SHZ/USD/LIABILITY-ATTESTATION/V1';
export const HEDGE_BOOK_DOMAIN = 'SHZ/USD/HEDGE-BOOK/V1';
const SATS = 100000000n, MICROS = 1000000n;

/** Accept an independently signed UTXO view, with full caveats on source-chain verification. */
function coin(cert, keys, expected, policy) {
  const c = authSigned(cert, keys, COIN, 'Bitcoin outpoint');
  demand(c.network === policy.bitcoinNetwork && c.asset === 'BTC' && c.purpose === expected.purpose, 'UTXO domain or purpose substitution');
  demand(c.owner === policy.issuer && c.unspent === true && c.confirmations >= policy.minConfirmations && Number.isSafeInteger(c.confirmations), 'UTXO unspentness or confirmations unauthenticated');
  hex32(c.tipBlockHash, 'observed chain tip');
  hex32(c.spendingPolicyDigest, 'spend authorization policy');
  demand(c.spendingPolicyDigest === expected.spendPolicyDigest, 'funding or recovery spend-policy substitution');
  if (policy.expectedTipBlockHash) demand(c.tipBlockHash === policy.expectedTipBlockHash, 'independently pinned chain tip mismatch');
  const id = bitcoinOutpoint(c.network, c.txid, c.vout);
  return { id, sats: positive(c.valueSats, 'coin value'), signedSource: cert.keyId };
}

/**
 * One BTC-hedged short vault. Stress prices are supplied by an independently pinned policy.
 * This proves arithmetic on signed observer reports, not funding consensus, liquidation safety,
 * or a continuous-price peg. Position value = capped contractual short payout.
 */
export function checkHedgeBook(book, policy) {
  demand(book?.issuer === policy.issuer && book.assetId === policy.assetId && book.network === policy.bitcoinNetwork, 'wrong SHZ issuer/asset/network');
  demand(Number.isSafeInteger(book.epoch) && book.epoch > 0 && book.epoch === policy.epoch, 'wrong hedge epoch');
  demand(Array.isArray(book.positions) && book.positions.length > 0 && book.positions.length <= 64, 'invalid hedge positions');
  demand(Array.isArray(book.reserves) && book.reserves.length <= 64, 'invalid hedge reserves');
  const bookHash = digest(HEDGE_BOOK_DOMAIN, book);
  hex32(policy.expectedBookHash, 'pinned SHZ book hash');
  demand(bookHash === policy.expectedBookHash, 'SHZ book does not open independently pinned commitment');
  const liab = authSigned(book.liability, policy.liabilityAuditors, LIABILITY, 'SHZ liability');
  demand(liab.issuer === book.issuer && liab.assetId === book.assetId && liab.epoch === book.epoch && liab.bitcoinNetwork === book.network, 'liability domain substitution');
  hex32(liab.oracleEpochDigest, 'authenticated oracle epoch');
  demand(liab.oracleEpochDigest === policy.oracleEpochDigest, 'SHZ price epoch substitution');
  hex32(liab.taprootAssetGenesis, 'Taproot Asset genesis');
  hex32(liab.liabilityRoot, 'pinned holder liability root');
  demand(liab.liabilityRoot === policy.expectedLiabilityRoot, 'untrusted holder supply root');
  const outstanding = u64(liab.outstandingMicros, 'SHZ outstanding');
  const pending = u64(liab.pendingRedemptionMicros, 'SHZ unpaid redemptions');
  const required = outstanding + pending;
  const used = new Set(), ids = new Set();
  let reserveSats = 0n;
  for (const r of book.reserves) {
    const c = coin(r.attestation, policy.coinObservers, {purpose:'SHZ_RESERVE',spendPolicyDigest:r.spendPolicyDigest}, policy);
    demand(!used.has(c.id), 'duplicate BTC reserve outpoint');
    used.add(c.id); reserveSats += c.sats;
  }
  const positions = [];
  for (const pos of book.positions) {
    demand(typeof pos.id === 'string' && pos.id.length > 0 && !ids.has(pos.id), 'duplicate or missing position ID');
    ids.add(pos.id);
    const c = coin(pos.attestation, policy.coinObservers, {purpose:'SHZ_DLC',spendPolicyDigest:pos.spendPolicyDigest}, policy);
    demand(!used.has(c.id), 'duplicated BTC collateral outpoint');
    used.add(c.id);
    const shortMargin = positive(pos.shortMarginSats, 'short collateral');
    const longMargin = positive(pos.counterpartyMarginSats, 'counterparty collateral');
    const overhead = u64(pos.fundingOverheadSats, 'funding overhead');
    demand(c.sats === shortMargin + longMargin + overhead, 'DLC funding value not conserved');
    const n = positive(pos.notionalUsd, 'USD notional');
    const entry = positive(pos.entryPriceUsd, 'entry price');
    positions.push({notionalUsd:n, entryUsd:entry, shortMargin, longMargin, positionId:pos.id});
  }
  demand(policy.stressPricesUsd?.length >= 3 && policy.stressPricesUsd.length <= 64, 'stress grid too small');
  let previous = 0n;
  const stress = policy.stressPricesUsd.map(priceText => {
    const price = positive(priceText, 'stress price');
    demand(price > previous, 'stress price grid must be strictly increasing');
    previous=price;
    let claimSats = reserveSats;
    let cappedOutcomes = 0;
    for(const p of positions){
      // 1x short: N*(1/P - 1/P0) BTC; round only once at the contract level.
      const pnl = halfAway(p.notionalUsd * SATS * (p.entryUsd - price), price * p.entryUsd);
      const uncapped = p.shortMargin + pnl;
      const claim = min(max(0n, uncapped), p.shortMargin+p.longMargin);
      if (claim !== uncapped) cappedOutcomes++;
      claimSats += claim;
    }
    const fee = u64(policy.estimatedExitFeesSats, 'exit fee budget');
    const haircut = u64(policy.insolvencyHaircutSats, 'stress haircut');
    demand(claimSats >= fee + haircut, 'fee and haircut exceed realizable BTC');
    const availableSats = claimSats-fee-haircut;
    const usdMicros = availableSats*price*MICROS/SATS;
    return {priceUsd:price.toString(),recoverableSats:availableSats.toString(),recoverableUsdMicros:usdMicros.toString(),cappedOutcomes,passes:usdMicros>=required};
  });
  const worst = stress.reduce((a,b)=>BigInt(a.recoverableUsdMicros)<BigInt(b.recoverableUsdMicros)?a:b);
  const failedStress = stress.find(x => !x.passes);
  demand(!failedStress, `stress insolvency at BTC/USD ${failedStress?.priceUsd ?? 'unknown'}`);
  return {issuer:book.issuer,assetId:book.assetId,epoch:book.epoch,bookHash,liabilityRoot:liab.liabilityRoot,
    assetGenesis:liab.taprootAssetGenesis,outstandingMicros:outstanding.toString(),pendingRedemptionMicros:pending.toString(),
    liabilityMicros:required.toString(),worstStressPriceUsd:worst.priceUsd,worstRecoverableUsdMicros:worst.recoverableUsdMicros,
    stress,resourceIds:[...used].sort(),verificationTier:'PINNED_SIGNED_UTXO_SNAPSHOT_AND_STRESS_GRID',
    nativeTaprootAssetProofVerified:false,btcSpendingEnforced:false};
}
