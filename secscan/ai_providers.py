"""Official, stateless provider adapters. Keys and requests are memory-only."""
from .i18n import tr
import json
import urllib.error
import urllib.request
import re
from dataclasses import dataclass
from urllib.parse import urlparse
from .diagnostics import diagnostic
from abc import ABC, abstractmethod

PROVIDER_BASE_URLS = {
    "deepseek": ("https://api.deepseek.com", "https://api.deepseek.com/v1"),
    "qwen": ("https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
             "https://dashscope.aliyuncs.com/compatible-mode/v1",
             "https://dashscope-us.aliyuncs.com/compatible-mode/v1"),
}
OFFICIAL_ENDPOINTS = {"https://api.openai.com/v1/responses", "https://api.anthropic.com/v1/messages"}
OFFICIAL_ENDPOINTS.update(base + "/chat/completions" for bases in PROVIDER_BASE_URLS.values() for base in bases)


class ProviderError(RuntimeError):
    def __init__(self, message, info=None, usage=None):
        super().__init__(message)
        self.diagnostic = info or diagnostic("provider_request_error", "provider_failure", message)
        self.usage = usage or {}


@dataclass(frozen=True)
class Capabilities:
    supports_json_schema: bool = False
    supports_json_object: bool = False
    supports_responses_api: bool = False
    supports_chat_completions: bool = True
    supports_system_prompt: bool = True
    supports_streaming: bool = True
    disable_thinking: bool = False
    max_output_tokens: int = 8192


def allowed_base(name, base):
    if not isinstance(base, str):
        return False
    if base in PROVIDER_BASE_URLS.get(name, ()):
        return True
    return name == "qwen" and bool(re.fullmatch(r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:ap-southeast-1|cn-beijing|us-east-1)\.maas\.aliyuncs\.com/compatible-mode/v1", base))


def capabilities(name, model):
    model = resolve_model(name, model)
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}", model):
        raise ProviderError(tr("Modelo inválido; informe somente o identificador oficial do modelo."), diagnostic("configuration_error", "invalid_model", tr("Identificador de modelo inválido.")))
    m = model.lower()
    if name == "openai":
        return Capabilities(supports_json_schema=True, supports_responses_api=True, supports_chat_completions=False)
    if name == "anthropic":
        return Capabilities(supports_json_schema=True, supports_chat_completions=False)
    if name == "deepseek":
        return Capabilities(supports_json_object=True, supports_responses_api=True, max_output_tokens=393216)
    if name == "qwen":
        if "thinking" in m or m.startswith("qwq"):
            raise ProviderError(tr("Este modelo exige thinking/streaming não suportado pela revisão atual. Escolha um modelo não thinking."),
                                diagnostic("unsupported_feature", "thinking_model", tr("Modelo somente thinking incompatível com esta revisão estruturada.")))
        native = m.startswith(("qwen3.7-plus", "qwen3.7-flash", "qwen3.7-max", "qwen3.8-max", "qwen3.8-flash"))
        json_mode = native or m.startswith(("qwen-plus", "qwen-max", "qwen-flash", "qwen-turbo", "qwen-long", "qwen3", "qwen2.5"))
        if m.startswith("qwen2.5") and ("coder" in m or "math" in m):
            json_mode = False
        return Capabilities(supports_json_schema=native, supports_json_object=json_mode,
                            disable_thinking=not native and m.startswith(("qwen-plus", "qwen-flash", "qwen-turbo", "qwen3")) and "coder" not in m,
                            max_output_tokens=8192)
    raise ProviderError(tr("Provider não suportado."))


def resolve_model(name, model):
    if name != 'deepseek' or not isinstance(model, str):
        return model
    aliases = {'deepseek-v4-pro-0813':'deepseek-v4-pro', 'deepseek-v4-flash':'deepseek-flash', 'deepseek-v4-flash-vision-exp':'deepseek-flash'}
    resolved = aliases.get(model.lower(), model.lower())
    if resolved not in {'deepseek-v4-pro', 'deepseek-flash'}:
        raise ProviderError(tr('Modelo DeepSeek inválido ou legado descontinuado. Use deepseek-v4-pro ou deepseek-flash.'),
                            diagnostic('configuration_error','deepseek_model','Use o identificador da API: deepseek-v4-pro ou deepseek-flash. DeepSeek-V4-Pro-0813 é a versão do modelo.'))
    return resolved


def http_diagnostic(error, provider, model):
    # Inspect a bounded JSON error solely to map known categories. Never copy its prose.
    try:
        payload = json.loads(error.read(16384))
        node = payload.get("error", payload) if isinstance(payload, dict) else {}
        code = node.get("code", "") if isinstance(node, dict) else ""
        message = node.get("message", "") if isinstance(node, dict) else ""
        text = (str(code) + " " + str(message)).lower()
    except (ValueError, OSError):
        code, text = "", ""
    finally:
        error.close()
    status = error.code
    kind, reason = "provider_request_error", tr("Requisição rejeitada; verifique modelo, região, limites e configuração.")
    if status in (401, 403) or any(x in text for x in ("invalidapikey", "invalid_api_key", "authentication")):
        kind, reason = "authentication_error", tr("Autenticação recusada; verifique a chave e sua região/permissões.")
    elif any(x in text for x in ("modelnotfound", "model_not_found", "model does not exist", "model unavailable")):
        kind, reason = "configuration_error", tr("Modelo indisponível nesta conta/região; confirme seu identificador.")
    elif any(x in text for x in ("response_format", "response format", "json_schema", "json mode", "enable_thinking")):
        kind, reason = "unsupported_feature", tr("Formato de resposta ou modo thinking incompatível com o modelo selecionado.")
    elif "workspace" in text:
        kind, reason = "configuration_error", tr("Workspace ausente ou incompatível com a chave/região. Verifique a Base URL oficial.")
    elif any(x in text for x in ("max_tokens", "context length", "token limit", "input too long")):
        kind, reason = "configuration_error", tr("Limite de tokens/contexto incompatível; reduza o grupo de arquivos ou limite de saída.")
    elif status == 404:
        kind, reason = "network_error", tr("Endpoint ou modelo indisponível; verifique região/workspace.")
    elif status in (402, 429):
        reason = tr("Quota, saldo ou limite de requisições indisponível.")
    elif status >= 500:
        kind, reason = "network_error", tr("Serviço do provider indisponível; tente novamente mais tarde.")
    known_codes = {"invalid_api_key", "InvalidApiKey", "ModelNotFound", "model_not_found", "InvalidParameter", "InvalidParameter.UnsupportedResponseFormat", "unsupported_response_format", "insufficient_quota", "rate_limit_exceeded", "InvalidParameter.Range", "InvalidParameterValue"}
    summary = tr('Requisição recusada por {v0}: HTTP {v1}. {v2}', v0=provider, v1=status, v2=reason)
    return diagnostic(kind, str(status), summary, recoverable=status in (429, 500, 502, 503, 504),
                      provider=provider, model=model, endpoint="chat/completions" if provider in {"deepseek", "qwen"} else "structured_output",
                      http_status=status, provider_error_code=code if code in known_codes else "unclassified")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError(tr("O provider tentou redirecionar a requisição; envio interrompido."))


def post_json(url: str, headers: dict, body: dict, timeout: int) -> dict:
    if url not in OFFICIAL_ENDPOINTS and not (url.endswith('/chat/completions') and allowed_base('qwen', url[:-len('/chat/completions')])):
        raise ProviderError(tr("Endpoint de IA não permitido; apenas APIs oficiais configuradas são aceitas."))
    # No SDK retry cache, local sessions, response files or provider exception bodies.
    request = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                                     headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(8 * 1024 * 1024 + 1)
        if len(payload) > 8 * 1024 * 1024:
            raise ProviderError("Resposta do provider excede o limite permitido.")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ProviderError(tr("Resposta do provider inválida."))
        return value
    except urllib.error.HTTPError as error:
        host = urlparse(url).hostname or ''
        provider = 'qwen' if 'aliyuncs.com' in host else 'deepseek' if 'deepseek.com' in host else 'anthropic' if 'anthropic.com' in host else 'openai'
        info = http_diagnostic(error, provider, body.get('model'))
        raise ProviderError(info['summary'], info) from None
    except json.JSONDecodeError:
        message = tr("Provider retornou JSON inválido.")
        raise ProviderError(message, diagnostic('provider_request_error', 'invalid_json', message)) from None
    except TimeoutError:
        message = tr("Provider excedeu o tempo limite.")
        raise ProviderError(message, diagnostic('timeout', 'provider_timeout', message, recoverable=True)) from None
    except (urllib.error.URLError, OSError, ValueError):
        message = tr("Falha de conexão, timeout ou JSON inválido na resposta do provider.")
        raise ProviderError(message, diagnostic("network_error", "connection_or_json", message, recoverable=True)) from None


class AIProvider(ABC):
    name: str

    def validate_key(self, key: str) -> bool:
        # Authentication itself is validated by the first official API request.
        return bool(key.strip()) and not any(char in key for char in "\r\n")

    def test_connection(self, key, model):
        if not self.validate_key(key):
            raise ProviderError(tr("Informe uma API key para testar a conexão."))
        schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False}
        text, _ = self.scan(key=key, model=model, guide='Return only JSON: {"ok": true}.', bundle='Connection test. No source files.',
                            schema=schema, timeout=10, max_output_tokens=128, purpose='connection_test')
        try:
            import jsonschema
            jsonschema.validate(json.loads(text), schema)
        except (ValueError, jsonschema.ValidationError):
            raise ProviderError(tr("Provider respondeu, mas o JSON do teste é inválido."), diagnostic("provider_request_error", "invalid_json", tr("Resposta do teste não corresponde ao schema."))) from None
        return {"connected": True, "summary": tr("Conectado · autenticação, modelo e JSON validados. Nenhum código enviado.")}

    @abstractmethod
    def scan(self, *, key: str, model: str, guide: str, bundle: str, schema: dict,
             timeout: int, max_output_tokens: int, purpose='review') -> tuple[str, dict]:
        raise NotImplementedError

    @abstractmethod
    def parse_response(self, response: dict) -> tuple[str, dict]:
        raise NotImplementedError


class OpenAIProvider(AIProvider):
    name = "openai"

    def scan(self, *, key, model, guide, bundle, schema, timeout, max_output_tokens, purpose='review'):
        body = {"model": model, "store": False, "instructions": guide,
                "input": [{"role": "user", "content": [{"type": "input_text", "text": bundle}]}],
                "text": {"format": {"type": "json_schema", "name": "security_findings", "strict": True, "schema": schema}},
                "max_output_tokens": max_output_tokens}
        response = post_json("https://api.openai.com/v1/responses", {"Authorization": "Bearer " + key}, body, timeout)
        return self.parse_response(response)

    def parse_response(self, response):
        if response.get("status") not in (None, "completed"):
            raise ProviderError("Resposta OpenAI incompleta; limite de saída ou falha do provider.")
        text = []
        for output in response.get("output", []):
            for part in output.get("content", []):
                if part.get("type") == "refusal":
                    raise ProviderError("O provider recusou a revisão deste grupo de arquivos.")
                if part.get("type") == "output_text":
                    text.append(part.get("text", ""))
        usage = response.get("usage") or {}
        return "".join(text), usage


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def scan(self, *, key, model, guide, bundle, schema, timeout, max_output_tokens, purpose='review'):
        body = {"model": model, "max_tokens": max_output_tokens, "system": guide,
                "messages": [{"role": "user", "content": bundle}],
                "output_config": {"format": {"type": "json_schema", "schema": schema}}}
        response = post_json("https://api.anthropic.com/v1/messages", {"x-api-key": key, "anthropic-version": "2023-06-01"}, body, timeout)
        return self.parse_response(response)

    def parse_response(self, response):
        if response.get("stop_reason") in {"max_tokens", "refusal"}:
            raise ProviderError("Resposta Anthropic incompleta ou recusada.")
        text = "".join(x.get("text", "") for x in response.get("content", []) if x.get("type") == "text")
        return text, response.get("usage") or {}


class CompatibleJSONProvider(AIProvider):
    """Official JSON mode, followed by the same local strict schema validation."""
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or PROVIDER_BASE_URLS[self.name][0]).rstrip("/")
        if not allowed_base(self.name, self.base_url):
            raise ProviderError(tr("Base URL não permitida. Selecione um endpoint oficial do provider."))

    def scan(self, *, key, model, guide, bundle, schema, timeout, max_output_tokens, purpose='review'):
        model = resolve_model(self.name, model)
        caps = capabilities(self.name, model)
        body = {"model": model, "messages": [{"role": "system", "content": guide + "\nResponda em JSON conforme este schema: " + json.dumps(schema)},
                                               {"role": "user", "content": bundle}],
                "max_tokens": min(max_output_tokens, caps.max_output_tokens), "stream": False}
        if caps.supports_json_schema:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": "security_findings", "strict": True, "schema": schema}}
        elif caps.supports_json_object:
            body["response_format"] = {"type": "json_object"}
        if self.name == "qwen" and caps.disable_thinking:
            body["enable_thinking"] = False
        if self.name == 'deepseek' and purpose == 'connection_test':
            body['thinking'] = {'type': 'disabled'}
        response = post_json(self.base_url + "/chat/completions", {"Authorization": "Bearer " + key}, body, timeout)
        return self.parse_response(response)

    def parse_response(self, response):
        choices = response.get("choices")
        usage = response.get('usage')
        usage = usage if isinstance(usage, dict) else {}
        prompt_details = usage.get('prompt_tokens_details')
        prompt_details = prompt_details if isinstance(prompt_details, dict) else {}
        completion_details = usage.get('completion_tokens_details')
        completion_details = completion_details if isinstance(completion_details, dict) else {}
        safe_usage = {"input_tokens":usage.get('prompt_tokens'), "output_tokens":usage.get('completion_tokens'),
                      'cached_input_tokens':usage.get('prompt_cache_hit_tokens', prompt_details.get('cached_tokens')),
                      'reasoning_tokens':completion_details.get('reasoning_tokens')}
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            message = tr('Provider retornou JSON inválido.')
            raise ProviderError(message, diagnostic('provider_request_error','invalid_json',message,recoverable=True),safe_usage)
        reason = choices[0].get('finish_reason')
        if reason is not None and not isinstance(reason,str):
            message = tr('Provider retornou JSON inválido.')
            raise ProviderError(message,diagnostic('provider_request_error','invalid_json',message,recoverable=True),safe_usage)
        if reason not in ('stop', None):
            truncated = reason == 'length'
            message = tr('Resposta truncada pelo limite de tokens de saída; o grupo precisa de nova tentativa.') if truncated else tr('Provider recusou ou não concluiu este grupo de revisão.')
            code = 'output_limit' if truncated else 'refusal_or_incomplete'
            raise ProviderError(message, diagnostic('provider_request_error', code, message, recoverable=truncated,
                                finish_reason=reason if reason in {'length','content_filter','tool_calls','insufficient_system_resource'} else 'unknown'), safe_usage)
        message = choices[0].get('message')
        text = message.get('content') if isinstance(message,dict) and not message.get('refusal') else None
        if not isinstance(text, str) or not text.strip():
            error = tr("Provider não retornou JSON de findings.")
            code = 'refusal_or_incomplete' if isinstance(message,dict) and message.get('refusal') else 'invalid_json'
            raise ProviderError(error,diagnostic('provider_request_error',code,error,recoverable=code=='invalid_json'),safe_usage)
        return text, safe_usage


class DeepSeekProvider(CompatibleJSONProvider):
    name = "deepseek"


class QwenProvider(CompatibleJSONProvider):
    name = "qwen"


PROVIDERS = {"openai": OpenAIProvider, "anthropic": AnthropicProvider, "deepseek": DeepSeekProvider, "qwen": QwenProvider}


def create_provider(name: str, base_url: str | None = None) -> AIProvider:
    provider = PROVIDERS[name]
    return provider(base_url) if issubclass(provider, CompatibleJSONProvider) else provider()
