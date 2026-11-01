"""TrustLens AI - Meta Model API Client

Dedicated, production-grade client for Meta Model API (Muse Spark 1.3 & Muse Voice Transcribe).
Handles text reasoning, multimodal input, structured output, tool-calling,
bounded exponential backoff, usage/latency metrics, and explicit error taxonomy.
"""

import asyncio
import base64
import json
import time
from typing import Any, Dict, List, Optional, Type, TypeVar
import httpx
from pydantic import BaseModel
from app.core.config import settings
from app.core.logging import logger

T = TypeVar("T", bound=BaseModel)


# Explicit Error Taxonomy
class MetaAPIError(Exception):
    """Base exception for all Meta API failures."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class MetaAuthError(MetaAPIError):
    """Authentication or authorization failure (HTTP 401/403)."""
    pass


class MetaRateLimitError(MetaAPIError):
    """Rate limit or concurrent quota exceeded (HTTP 429)."""
    pass


class MetaQuotaError(MetaAPIError):
    """Account quota or credit limit exhausted."""
    pass


class MetaServiceError(MetaAPIError):
    """Meta API upstream service failure (HTTP 500/502/503/504)."""
    pass


class MetaTimeoutError(MetaAPIError):
    """Request exceeded configured timeout."""
    pass


class MetaCapabilityUnavailableError(MetaAPIError):
    """Requested model capability (e.g. search grounding, tool) is disabled for this account."""
    pass


class MetaResponseMetadata(BaseModel):
    model_id: str
    latency_ms: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    grounding_metadata: Optional[Dict[str, Any]] = None


class MetaChatResponse(BaseModel):
    content: str
    metadata: MetaResponseMetadata
    raw_response: Dict[str, Any]
    tool_calls: Optional[List[Dict[str, Any]]] = None


class TranscriptionSegment(BaseModel):
    start: float
    end: float
    text: str
    speaker: Optional[str] = None


class MetaTranscriptionResponse(BaseModel):
    text: str
    language: Optional[str] = None
    duration_seconds: Optional[float] = None
    segments: List[TranscriptionSegment] = []
    metadata: MetaResponseMetadata


class MetaModelClient:
    """Production client for Meta Model API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_id: Optional[str] = None,
        voice_model_id: Optional[str] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
    ):
        self.api_key = api_key or settings.MODEL_API_KEY
        self.base_url = (base_url or settings.META_BASE_URL).rstrip("/")
        self.model_id = model_id or settings.META_MODEL_ID
        self.voice_model_id = voice_model_id or settings.META_VOICE_MODEL_ID
        self.timeout = timeout or settings.META_TIMEOUT_SECONDS
        self.max_retries = max_retries or settings.META_MAX_RETRIES

    @property
    def is_configured(self) -> bool:
        """Returns True if a non-empty API key is present."""
        return bool(self.api_key and self.api_key.strip())

    def _get_headers(self) -> Dict[str, str]:
        if not self.is_configured:
            raise MetaAuthError(
                "MODEL_API_KEY is not configured. Set MODEL_API_KEY in environment or .env.",
                status_code=401,
            )
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "TrustLens-Backend/1.0",
        }

    async def generate_reasoning(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = None,
        response_format: Optional[Dict[str, Any]] = None,
        search_grounding: bool = False,
    ) -> MetaChatResponse:
        """Dispatches an inference request to Meta Model API with bounded retries."""
        headers = self._get_headers()
        url = f"{self.base_url}/chat/completions"

        payload: Dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            payload["tools"] = tools
            if tool_choice:
                payload["tool_choice"] = tool_choice

        if response_format:
            payload["response_format"] = response_format

        if search_grounding:
            # Meta grounding parameter / search tool
            payload["search_grounding"] = True

        last_error: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            start_time = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, headers=headers, json=payload)

                latency_ms = (time.perf_counter() - start_time) * 1000.0

                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if not choices:
                        raise MetaAPIError("Meta API returned empty choices list", status_code=200, details=data)

                    message_obj = choices[0].get("message", {})
                    content = message_obj.get("content") or ""
                    tool_calls = message_obj.get("tool_calls")

                    usage = data.get("usage", {})
                    grounding = data.get("grounding_metadata") or choices[0].get("grounding_metadata")

                    metadata = MetaResponseMetadata(
                        model_id=data.get("model", self.model_id),
                        latency_ms=round(latency_ms, 2),
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                        total_tokens=usage.get("total_tokens", 0),
                        grounding_metadata=grounding,
                    )

                    return MetaChatResponse(
                        content=content,
                        metadata=metadata,
                        raw_response=data,
                        tool_calls=tool_calls,
                    )

                # Error handling
                err_data = {}
                try:
                    err_data = resp.json()
                except Exception:
                    err_data = {"raw_text": resp.text[:500]}

                err_msg = err_data.get("error", {}).get("message") if isinstance(err_data.get("error"), dict) else str(err_data)

                if resp.status_code in (401, 403):
                    raise MetaAuthError(f"Meta API Auth Failure: {err_msg}", status_code=resp.status_code, details=err_data)
                elif resp.status_code == 429:
                    raise MetaRateLimitError(f"Meta API Rate Limit Exceeded: {err_msg}", status_code=429, details=err_data)
                elif resp.status_code in (500, 502, 503, 504):
                    raise MetaServiceError(f"Meta API Service Outage ({resp.status_code}): {err_msg}", status_code=resp.status_code, details=err_data)
                elif resp.status_code == 400 and "grounding" in err_msg.lower():
                    raise MetaCapabilityUnavailableError(f"Search grounding unavailable: {err_msg}", status_code=400, details=err_data)
                else:
                    raise MetaAPIError(f"Meta API HTTP {resp.status_code}: {err_msg}", status_code=resp.status_code, details=err_data)

            except (httpx.TimeoutException, asyncio.TimeoutError) as e:
                last_error = MetaTimeoutError(f"Request to Meta API timed out after {self.timeout}s")
            except (MetaRateLimitError, MetaServiceError) as e:
                last_error = e
            except MetaAPIError:
                raise
            except Exception as e:
                last_error = MetaAPIError(f"Unexpected error communicating with Meta API: {str(e)}")

            # Exponential backoff for retryable errors
            if attempt < self.max_retries:
                backoff_sec = 2 ** (attempt - 1)
                logger.warning(f"Meta API call attempt {attempt} failed ({last_error}). Retrying in {backoff_sec}s...")
                await asyncio.sleep(backoff_sec)

        raise last_error or MetaAPIError("Exceeded maximum retries for Meta API call")

    async def generate_structured(
        self,
        messages: List[Dict[str, Any]],
        schema: Type[T],
        temperature: float = 0.1,
    ) -> tuple[T, MetaResponseMetadata]:
        """Generates a structured result validated against a Pydantic schema."""
        # Inject schema instruction if not already present
        schema_json = json.dumps(schema.model_json_schema(), indent=2)
        augmented_messages = list(messages)

        # Append schema expectation to the system or developer message
        schema_prompt = (
            f"\n\n[MANDATORY FORMAT REQUIREMENT]\n"
            f"You MUST output valid JSON conforming strictly to the following JSON Schema. "
            f"Output ONLY the JSON object, with no markdown code fences, greetings, or conversational remarks.\n"
            f"Schema:\n{schema_json}"
        )

        if augmented_messages and augmented_messages[0].get("role") in ("system", "developer"):
            augmented_messages[0] = {
                "role": augmented_messages[0]["role"],
                "content": augmented_messages[0]["content"] + schema_prompt,
            }
        else:
            augmented_messages.insert(0, {"role": "system", "content": schema_prompt})

        response = await self.generate_reasoning(
            messages=augmented_messages,
            temperature=temperature,
            response_format={"type": "json_object"},
        )

        content = response.content.strip()
        # Clean potential markdown wrapping if present
        if content.startswith("```"):
            lines = content.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            content = "\n".join(lines).strip()

        try:
            validated = schema.model_validate_json(content)
            return validated, response.metadata
        except Exception as e:
            logger.error(f"Failed to validate Meta API structured output against schema {schema.__name__}: {e}. Raw content: {content[:300]}")
            raise MetaAPIError(
                f"Model output failed schema validation for {schema.__name__}: {str(e)}",
                details={"raw_content": content},
            )

    async def analyze_image_structured(
        self,
        image_bytes: bytes,
        mime_type: str,
        prompt: str,
        schema: Type[T],
        temperature: float = 0.1,
    ) -> tuple[T, MetaResponseMetadata]:
        """Analyzes an image using Meta Muse Spark multimodal reasoning with structured schema validation."""
        if not self.is_configured:
            raise MetaAuthError(
                "MODEL_API_KEY is not configured for image analysis.",
                status_code=401,
            )

        b64_data = base64.b64encode(image_bytes).decode("utf-8")
        data_uri = f"data:{mime_type};base64,{b64_data}"

        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": data_uri}},
                ],
            }
        ]

        return await self.generate_structured(
            messages=messages,
            schema=schema,
            temperature=temperature,
        )

    async def transcribe_audio(
        self,
        audio_bytes: bytes,
        filename: str = "audio.wav",
        mime_type: str = "audio/wav",
    ) -> MetaTranscriptionResponse:
        """Transcribes audio using Muse Voice Transcribe through the official endpoint."""
        if not self.is_configured:
            raise MetaAuthError("MODEL_API_KEY is not configured.", status_code=401)

        url = f"{self.base_url}/audio/transcriptions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "TrustLens-Backend/1.0",
        }

        files = {
            "file": (filename, audio_bytes, mime_type),
        }
        data = {
            "model": self.voice_model_id,
            "response_format": "verbose_json",
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, files=files, data=data)

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 200:
                result = resp.json()
                segments = []
                for s in result.get("segments", []):
                    segments.append(
                        TranscriptionSegment(
                            start=float(s.get("start", 0.0)),
                            end=float(s.get("end", 0.0)),
                            text=s.get("text", "").strip(),
                            speaker=s.get("speaker"),
                        )
                    )

                metadata = MetaResponseMetadata(
                    model_id=self.voice_model_id,
                    latency_ms=round(latency_ms, 2),
                )

                return MetaTranscriptionResponse(
                    text=result.get("text", "").strip(),
                    language=result.get("language"),
                    duration_seconds=result.get("duration"),
                    segments=segments,
                    metadata=metadata,
                )

            err_data = {}
            try:
                err_data = resp.json()
            except Exception:
                err_data = {"raw_text": resp.text[:500]}

            err_msg = err_data.get("error", {}).get("message") if isinstance(err_data.get("error"), dict) else str(err_data)

            if resp.status_code in (401, 403):
                raise MetaAuthError(f"Transcription Auth Error: {err_msg}", status_code=resp.status_code)
            elif resp.status_code == 429:
                raise MetaRateLimitError(f"Transcription Rate Limit: {err_msg}", status_code=429)
            else:
                raise MetaServiceError(f"Transcription Service Failure ({resp.status_code}): {err_msg}", status_code=resp.status_code)

        except (httpx.TimeoutException, asyncio.TimeoutError):
            raise MetaTimeoutError(f"Audio transcription timed out after {self.timeout}s")

    async def check_connectivity(self) -> Dict[str, Any]:
        """Probes the Meta Model API to check credentials and permissions."""
        if not self.is_configured:
            return {
                "configured": False,
                "reachable": False,
                "model_id": self.model_id,
                "voice_model_id": self.voice_model_id,
                "error": "MODEL_API_KEY environment variable is not set",
            }

        url = f"{self.base_url}/models"
        headers = self._get_headers()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url, headers=headers)

            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("id") for m in data.get("data", [])]
                return {
                    "configured": True,
                    "reachable": True,
                    "status_code": 200,
                    "available_models": models,
                    "primary_model_available": self.model_id in models if models else True,
                    "voice_model_available": self.voice_model_id in models if models else True,
                }
            else:
                return {
                    "configured": True,
                    "reachable": False,
                    "status_code": resp.status_code,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as e:
            return {
                "configured": True,
                "reachable": False,
                "error": str(e),
            }


meta_client = MetaModelClient()
