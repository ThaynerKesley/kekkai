"""Transparent estimates from reported usage; no billing/account API calls."""
from .i18n import tr
import math

PRICE_DATE = '2026-10-26'
PRICE_URL = 'https://api-docs.deepseek.com/quick_start/pricing/'
# USD per million tokens, off-peak. Peak is twice off-peak in this snapshot.
DEEPSEEK_RATES = {'deepseek-v4-pro': (0.66, 0.022, 1.98), 'deepseek-flash': (0.15, 0.003, 0.60)}


def estimate_cost(provider, model, usage, pricing=None):
    incoming = usage.get('input_tokens', 0) or 0
    outgoing = usage.get('output_tokens', 0) or 0
    pricing = pricing or {}
    if pricing.get('input_per_million') is not None and pricing.get('output_per_million') is not None:
        amount = (incoming*pricing['input_per_million'] + outgoing*pricing['output_per_million'])/1_000_000
        return {'currency':'USD', 'minimum':round(amount, 6), 'maximum':round(amount, 6), 'basis':tr('Tarifas manuais, estimativa'), 'estimated':True}
    if provider != 'deepseek' or model not in DEEPSEEK_RATES:
        return None
    miss, hit, output = DEEPSEEK_RATES[model]
    cached = min(incoming, usage.get('cached_input_tokens', 0) or 0)
    amount = ((incoming-cached)*miss + cached*hit + outgoing*output)/1_000_000
    return {'currency':'USD', 'minimum':round(amount, 6), 'maximum':round(amount*2, 6),
            'basis':tr('Faixa off-peak/peak; entrada sem cache quando cache não informado'), 'estimated':True,
            'price_date':PRICE_DATE, 'source':PRICE_URL}


def estimate_plan(provider, model, groups, guide, schema, options):
    import json
    overhead = len(guide.encode('utf-8')) + len(json.dumps(schema).encode('utf-8')) + 1024
    # Code/token ratios vary. Explicit heuristic rather than claiming provider tokenization.
    incoming = sum(math.ceil((len(bundle.encode('utf-8'))+overhead)/3) for bundle, _ in groups)
    attempts = options.get('max_attempts', 2)
    base = int(options['max_output_tokens'])
    ceiling = max(base, int(options.get('max_retry_output_tokens', 32768)))
    cap = sum(min(base*4**attempt, ceiling) for attempt in range(attempts))*len(groups)
    return {'input_tokens_approx':incoming, 'groups':len(groups), 'max_requests':len(groups)*attempts,
            'output_token_budget':cap, 'heuristic':tr('bytes/3 + prompt/schema por grupo; não é tokenização exata'),
            'cost_at_output_budget':estimate_cost(provider, model, {'input_tokens':incoming*attempts,'output_tokens':cap}, options.get('pricing'))}
