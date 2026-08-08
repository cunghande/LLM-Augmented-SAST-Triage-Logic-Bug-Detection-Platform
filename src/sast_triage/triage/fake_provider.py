"""Fake TriageProvider phục vụ kiểm thử SAST Triage Platform.

Cung cấp implementation giả lập chạy cục bộ và ổn định, không gọi API mạng.

Cam kết bảo mật và toàn vẹn:
- Không sao chép mã nguồn, import, decorator, đường dẫn tuyệt đối hoặc secret canary vào TriageDecision.
- Output chỉ phụ thuộc tín hiệu `prompt_type` và trạng thái context.
- Không suy luận verdict từ rule_id, đường dẫn file hoặc severity.
- Không có side effect.
"""

from enum import Enum

from sast_triage.errors import SastTriageError
from sast_triage.models import (
    ModelConfidence,
    ModelVerdict,
    TriageDecision,
    TriageInput,
)


class FakeTriageProviderMode(str, Enum):
    """Các chế độ thực thi của FakeTriageProvider."""

    NORMAL = "normal"
    RAISE_TIMEOUT = "raise_timeout"
    RAISE_PROVIDER_ERROR = "raise_provider_error"


class FakeTriageProvider:
    """Provider giả lập dành cho kiểm thử ổn định và tái lập được."""

    def __init__(
        self,
        mode: FakeTriageProviderMode | str = FakeTriageProviderMode.NORMAL,
    ) -> None:
        if isinstance(mode, str):
            try:
                mode = FakeTriageProviderMode(mode.lower())
            except ValueError as exc:
                raise SastTriageError(
                    safe_message="Invalid mode specified for FakeTriageProvider.",
                    error_code="TRIAGE_INVALID_PROVIDER_MODE",
                    retryable=False,
                ) from exc
        elif not isinstance(mode, FakeTriageProviderMode):
            raise SastTriageError(
                safe_message="Invalid mode specified for FakeTriageProvider.",
                error_code="TRIAGE_INVALID_PROVIDER_MODE",
                retryable=False,
            )

        self._mode = mode

    @property
    def provider_name(self) -> str:
        """Trả về định danh provider ổn định."""
        return "fake"

    @property
    def model_version(self) -> str:
        """Trả về định danh model giả lập."""
        return "fake-triage-v1"

    @property
    def mode(self) -> FakeTriageProviderMode:
        """Trả về chế độ thực thi hiện tại."""
        return self._mode

    def triage(self, triage_input: TriageInput) -> TriageDecision:
        """Sinh ``TriageDecision`` ổn định từ ``TriageInput``.

        Args:
            triage_input: Payload TriageInput đã được validate.

        Returns:
            Model Pydantic TriageDecision có kết quả ổn định.

        Raises:
            SastTriageError: Khi input sai, giả lập timeout hoặc giả lập lỗi provider.
        """
        if not isinstance(triage_input, TriageInput):
            raise SastTriageError(
                safe_message="triage() requires a TriageInput instance.",
                error_code="TRIAGE_INVALID_INPUT",
                retryable=False,
            )

        # 1. Giả lập lỗi provider
        if self._mode == FakeTriageProviderMode.RAISE_TIMEOUT:
            raise SastTriageError(
                safe_message="FakeTriageProvider request timed out.",
                error_code="TRIAGE_PROVIDER_TIMEOUT",
                retryable=True,
            )

        if self._mode == FakeTriageProviderMode.RAISE_PROVIDER_ERROR:
            raise SastTriageError(
                safe_message="FakeTriageProvider encountered an internal provider error.",
                error_code="TRIAGE_PROVIDER_ERROR",
                retryable=False,
            )

        # 2. Ưu tiên xử lý trường hợp không có context
        if not triage_input.context.context_available:
            evidence = ["Ngữ cảnh mã nguồn không khả dụng."]
            if triage_input.context.missing_context_reasons:
                evidence.extend([r.value for r in triage_input.context.missing_context_reasons])

            return TriageDecision(
                model_verdict=ModelVerdict.NEEDS_REVIEW,
                model_confidence=ModelConfidence.LOW,
                summary="Provider giả lập yêu cầu review thủ công vì không có ngữ cảnh mã nguồn để kiểm chứng cơ chế lỗ hổng.",
                evidence=evidence,
                missing_information=["Cần ngữ cảnh mã nguồn đã làm sạch tại vị trí finding."],
                assumptions=["Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử."],
                model_version="fake-triage-v1",
                prompt_version=triage_input.prompt_version,
            )

        # 3. Tín hiệu kiểm thử tường minh từ prompt_type
        prompt_type = triage_input.prompt_type.strip().lower()

        if prompt_type == "fake.tp.high":
            return TriageDecision(
                model_verdict=ModelVerdict.LIKELY_TP,
                model_confidence=ModelConfidence.HIGH,
                summary="Provider giả lập đánh giá finding có khả năng là true positive với độ tin cậy cao theo kịch bản kiểm thử đã chọn.",
                evidence=["Kịch bản kiểm thử fake.tp.high được chọn rõ ràng trong prompt_type."],
                missing_information=[],
                assumptions=["Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử."],
                model_version="fake-triage-v1",
                prompt_version=triage_input.prompt_version,
            )

        if prompt_type == "fake.fp.high":
            return TriageDecision(
                model_verdict=ModelVerdict.LIKELY_FP,
                model_confidence=ModelConfidence.HIGH,
                summary="Provider giả lập đánh giá finding có khả năng là false positive với độ tin cậy cao theo kịch bản kiểm thử đã chọn.",
                evidence=["Kịch bản kiểm thử fake.fp.high được chọn rõ ràng trong prompt_type."],
                missing_information=[],
                assumptions=["Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử."],
                model_version="fake-triage-v1",
                prompt_version=triage_input.prompt_version,
            )

        if prompt_type == "fake.review.low":
            return TriageDecision(
                model_verdict=ModelVerdict.NEEDS_REVIEW,
                model_confidence=ModelConfidence.LOW,
                summary="Provider giả lập chưa đủ bằng chứng để kết luận và yêu cầu security reviewer kiểm tra thủ công.",
                evidence=["Kịch bản kiểm thử fake.review.low được chọn rõ ràng trong prompt_type."],
                missing_information=["Cần review thủ công chi tiết để xác nhận TP hoặc FP."],
                assumptions=["Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử."],
                model_version="fake-triage-v1",
                prompt_version=triage_input.prompt_version,
            )

        # 4. Quyết định mặc định
        return TriageDecision(
            model_verdict=ModelVerdict.NEEDS_REVIEW,
            model_confidence=ModelConfidence.MEDIUM,
            summary="Provider giả lập sử dụng quyết định mặc định và chuyển finding sang review thủ công.",
            evidence=["Không có kịch bản prompt_type chuyên biệt nên provider dùng nhánh mặc định."],
            missing_information=[],
            assumptions=["Kết quả này chỉ được tạo bởi FakeTriageProvider để kiểm thử."],
            model_version="fake-triage-v1",
            prompt_version=triage_input.prompt_version,
        )
