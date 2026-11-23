'use strict';

const { integer, identifier, commitment, MAX_PRICE_USD, SATS_PER_BTC } = require('./core');

// Integer USD prices and notionals are deliberately used in MNR-01. A later
// market schema must define tick precision and re-pin every payout table.
function inverseLongPnlSats(notionalUsd, entryPriceUsd, exitPriceUsd) {
  const n = integer(notionalUsd, 'notionalUsd', { zero: false });
  const entry = integer(entryPriceUsd, 'entryPriceUsd', { zero: false, max: MAX_PRICE_USD });
  const exit = integer(exitPriceUsd, 'exitPriceUsd', { zero: false, max: MAX_PRICE_USD });
  // BigInt division truncates toward zero. Each bilateral CET may round
  // independently, creating a 1-sat portfolio rounding residual.
  return n * SATS_PER_BTC * (exit - entry) / (entry * exit);
}

function validateOriginal(source) {
  if (!source || typeof source !== 'object' || Array.isArray(source)) throw new TypeError('original contract object required');
  const c = {
    id: identifier(source.id, 'original.id'),
    long: identifier(source.long, 'original.long'),
    short: identifier(source.short, 'original.short'),
    notionalUsd: integer(source.notionalUsd, 'original.notionalUsd', { zero: false }).toString(),
    entryPriceUsd: integer(source.entryPriceUsd, 'original.entryPriceUsd', { zero: false, max: MAX_PRICE_USD }).toString(),
    oracleEventId: identifier(source.oracleEventId, 'original.oracleEventId'),
    nettingSetId: identifier(source.nettingSetId, 'original.nettingSetId'),
    maturityHeight: integer(source.maturityHeight, 'original.maturityHeight', { zero: false }).toString()
  };
  if (c.long === c.short) throw new Error('bilateral DLC must have distinct parties');
  return c;
}

function positionPnl(contract, actor, priceUsd) {
  const longPnl = inverseLongPnlSats(contract.notionalUsd, contract.entryPriceUsd, priceUsd);
  if (actor === contract.long) return longPnl;
  if (actor === contract.short) return -longPnl;
  throw new Error(`party ${actor} has no leg in ${contract.id}`);
}

function buildMatchedCloseout({ original, closingParty, liquidityProvider, quote, outcomePricesUsd, currentHeight }) {
  const originalContract = validateOriginal(original);
  const actor = identifier(closingParty, 'closingParty');
  const maker = identifier(liquidityProvider, 'liquidityProvider');
  if (actor !== originalContract.long && actor !== originalContract.short) throw new Error('closing party is not a member of original DLC');
  if (maker === actor || maker === originalContract.long || maker === originalContract.short) {
    throw new Error('liquidity provider must be a distinct third party for MNR-01');
  }
  if (!quote || typeof quote !== 'object') throw new TypeError('quote required');
  const quoteId = identifier(quote.id, 'quote.id');
  const mark = integer(quote.closePriceUsd, 'quote.closePriceUsd', { zero: false, max: MAX_PRICE_USD });
  const quoteNotional = integer(quote.notionalUsd, 'quote.notionalUsd', { zero: false });
  const expiry = integer(quote.expiryHeight, 'quote.expiryHeight', { zero: false });
  const now = integer(currentHeight, 'currentHeight');
  if (now >= expiry) throw new Error('quote expired at the supplied chain height');
  if (quoteNotional.toString() !== originalContract.notionalUsd) throw new Error('partial close requires a separate split protocol');
  if (quote.oracleEventId !== originalContract.oracleEventId) throw new Error('oracle event mismatch');
  if (quote.nettingSetId !== originalContract.nettingSetId) throw new Error('netting domain mismatch');
  if (expiry > BigInt(originalContract.maturityHeight)) throw new Error('quote expires after original maturity');
  if (!Array.isArray(outcomePricesUsd) || outcomePricesUsd.length < 2 || outcomePricesUsd.length > 1024) {
    throw new Error('at least two and at most 1024 oracle outcomes required');
  }
  const outcomes = outcomePricesUsd.map((p, i) => integer(p, `outcomePricesUsd[${i}]`, { zero: false, max: MAX_PRICE_USD }));
  if (new Set(outcomes.map(x => x.toString())).size !== outcomes.length) throw new Error('duplicate outcome price');
  const sorted = [...outcomes].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  if (outcomes.some((p, i) => p !== sorted[i])) throw new Error('outcome prices must be ascending');
  const offset = {
    id: `offset:${quoteId}`,
    long: actor === originalContract.long ? maker : actor,
    short: actor === originalContract.long ? actor : maker,
    notionalUsd: originalContract.notionalUsd,
    entryPriceUsd: mark.toString(),
    oracleEventId: originalContract.oracleEventId,
    nettingSetId: originalContract.nettingSetId,
    maturityHeight: originalContract.maturityHeight
  };
  if (offset.id === originalContract.id) throw new Error('offset contract ID collides with original');
  const markedPnl = positionPnl(originalContract, actor, mark);
  const payoffGrid = outcomes.map(price => {
    const originalPnl = positionPnl(originalContract, actor, price);
    const offsetPnl = positionPnl(offset, actor, price);
    const sum = originalPnl + offsetPnl;
    return {
      outcomePriceUsd: price.toString(),
      originalPnlSats: originalPnl.toString(),
      offsetPnlSats: offsetPnl.toString(),
      combinedPnlSats: sum.toString(),
      markPnlSats: markedPnl.toString(),
      roundingResidualSats: (sum - markedPnl).toString()
    };
  });
  const maxResidual = payoffGrid.reduce((acc, r) => {
    const x = BigInt(r.roundingResidualSats);
    const abs = x < 0n ? -x : x;
    return abs > acc ? abs : acc;
  }, 0n);
  if (maxResidual > 1n) throw new Error('inverse offset does not cancel within the 1-sat rounding budget');
  const plan = {
    protocol: 'SHZ/MNR-01/synthetic/v1',
    originalContract,
    offsetContract: offset,
    closingParty: actor,
    liquidityProvider: maker,
    quoteId,
    quoteExpiryHeight: expiry.toString(),
    observedHeightFromUntrustedCaller: now.toString(),
    markPnlSats: markedPnl.toString(),
    outcomePricesUsd: outcomes.map(x => x.toString()),
    maxRoundingResidualSats: maxResidual.toString(),
    payoffGrid,
    execution: {
      status: 'PROPOSAL_ONLY',
      originalDlcPreserved: true,
      originalCollateralReleased: false,
      offsetDlcFunded: false,
      fundingStateVerified: false,
      quoteSignatureVerified: false,
      outcomeTableAuthenticated: false,
      multilateralSpendAuthorized: false,
      proofVerified: false,
      productionReady: false
    }
  };
  return { ...plan, planDigest: commitment('SHZ.MNR01.PLAN.v1', plan) };
}

function obligationsForOutcome(plan, priceUsd) {
  if (!plan || plan.protocol !== 'SHZ/MNR-01/synthetic/v1') throw new Error('unknown closeout plan');
  const price = integer(priceUsd, 'priceUsd', { zero: false, max: MAX_PRICE_USD }).toString();
  if (!plan.outcomePricesUsd.includes(price)) throw new Error('outcome is outside the declared payout grid');
  const positions = [plan.originalContract, plan.offsetContract];
  return positions.flatMap(c => {
    const pnl = inverseLongPnlSats(c.notionalUsd, c.entryPriceUsd, price);
    if (pnl === 0n) return [];
    return [{
      id: `${c.id}:${price}`,
      nettingSetId: c.nettingSetId,
      from: pnl > 0n ? c.short : c.long,
      to: pnl > 0n ? c.long : c.short,
      amountSats: (pnl > 0n ? pnl : -pnl).toString(),
      originContractId: c.id
    }];
  });
}

module.exports = { inverseLongPnlSats, positionPnl, buildMatchedCloseout, obligationsForOutcome };
