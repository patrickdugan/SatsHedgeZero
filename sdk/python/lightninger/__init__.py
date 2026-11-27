"""Lightninger agent SDK: delegated-key trading on the Lightninger testnet venue.

    from lightninger import Client, Agent
    agent = Agent(Client("http://127.0.0.1:8095"), agent_sk, grant_id)
    agent.perp_post("long", 50, 89_500)
    agent.start_autosigner()

USDT on the venue is a labelled demo asset. See docs/SHZ_AGENT_API.md.
"""
from .agent import Agent, check_draft, create_grant, new_key, pubkey_hex, revoke_grant, sign
from .client import Client, LightningerError
from .encoding import grant_id, intent_id, option_intent_id, perp_intent_id, revocation_id, spot_intent_id
from .ws import RpcError, Stream

__all__ = ["Agent", "Client", "LightningerError", "RpcError", "Stream", "check_draft", "create_grant", "grant_id", "intent_id",
           "new_key", "option_intent_id", "perp_intent_id", "pubkey_hex", "revocation_id", "revoke_grant", "sign", "spot_intent_id"]
__version__ = "1.0.0"
