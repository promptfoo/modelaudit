"""Typed bridge to the standalone package's test-only framework fixtures."""

from collections.abc import Callable
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

if TYPE_CHECKING:
    import pytest

_SOURCE = Path(__file__).resolve().parents[2] / "packages/modelaudit-picklescan/tests/framework_fixtures.py"
_SPEC = spec_from_file_location("modelaudit_test_framework_fixtures", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
_fixtures = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_fixtures)


class _UnpickleOracle(Protocol):
    def __call__(self, payload_path: Path, tmp_path: Path, *, mode: str, extension_code: int | None) -> None: ...


_PackageWriter = Callable[[Path], None]
_MarkerWriter = Callable[[Path, Path], None]
_assert_shadow_framework_unpickle_executes = cast(_UnpickleOracle, _fixtures._assert_shadow_framework_unpickle_executes)
_write_init_heavy_trusted_transformers_package = cast(
    _PackageWriter, _fixtures._write_init_heavy_trusted_transformers_package
)
_write_sitecustomize_trusting_site_packages = cast(_MarkerWriter, _fixtures._write_sitecustomize_trusting_site_packages)
_write_init_inert_setstate_transformers_package = cast(
    _MarkerWriter, _fixtures._write_init_inert_setstate_transformers_package
)
_write_rebindable_trusted_transformers_package = cast(
    _PackageWriter, _fixtures._write_rebindable_trusted_transformers_package
)
_write_import_side_effect_transformers_package = cast(
    _MarkerWriter, _fixtures._write_import_side_effect_transformers_package
)
_write_runtime_mutable_trusted_transformers_package = cast(
    _PackageWriter, _fixtures._write_runtime_mutable_trusted_transformers_package
)
_write_enum_trusted_transformers_package = cast(_PackageWriter, _fixtures._write_enum_trusted_transformers_package)
_write_rebindable_trusted_torch_utils_package = cast(
    _PackageWriter, _fixtures._write_rebindable_trusted_torch_utils_package
)
_write_cross_module_rebind_target_package = cast(_PackageWriter, _fixtures._write_cross_module_rebind_target_package)


class _SystemCommandPayloadFactory(Protocol):
    def __call__(self, command: str, system_getter: Callable[[], Any] | None = None) -> object: ...


SystemCommandPayload = cast(_SystemCommandPayloadFactory, _fixtures.SystemCommandPayload)


class _DupHeavyPayload(Protocol):
    def __call__(self, iterations: int) -> bytes: ...


class _MemoExpansionPayload(Protocol):
    def __call__(self, iterations: int, *, inert_writes: int = 0) -> bytes: ...


class _StorageProtocol0Payload(Protocol):
    def __call__(self, key: str, *, storage_qualname: str = "torch.FloatStorage", size: int | str = 1) -> bytes: ...


class _ShadowBuildPayload(Protocol):
    def __call__(self, protocol: int = 4) -> bytes: ...


_binary_magic_tensor_storage_bytes = cast(Callable[[], bytes], _fixtures._binary_magic_tensor_storage_bytes)
_clear_ultralytics_modules = cast(Callable[[], None], _fixtures._clear_ultralytics_modules)
_float_storage_element_count_for_bytes = cast(Callable[[bytes], int], _fixtures._float_storage_element_count_for_bytes)
_force_framework_metadata_unresolved = cast(
    "Callable[[pytest.MonkeyPatch], None]", _fixtures._force_framework_metadata_unresolved
)
_frame_first_large_malicious_eval_pickle_payload = cast(
    Callable[[], bytes], _fixtures._frame_first_large_malicious_eval_pickle_payload
)
_frame_first_raw_storage_bytes = cast(Callable[[], bytes], _fixtures._frame_first_raw_storage_bytes)
_large_proto0_system_payload = cast(Callable[[], bytes], _fixtures._large_proto0_system_payload)
_make_dup_heavy_pickle = cast(_DupHeavyPayload, _fixtures._make_dup_heavy_pickle)
_make_memo_expansion_pickle = cast(_MemoExpansionPayload, _fixtures._make_memo_expansion_pickle)
_make_pre_memoized_post_budget_stack_global_payload = cast(
    Callable[[bytes], bytes], _fixtures._make_pre_memoized_post_budget_stack_global_payload
)
_pickle_binint = cast(Callable[[int], bytes], _fixtures._pickle_binint)
_pickle_int_tuple = cast(Callable[[tuple[int, ...]], bytes], _fixtures._pickle_int_tuple)
_pickleish_tensor_storage_bytes = cast(Callable[[], bytes], _fixtures._pickleish_tensor_storage_bytes)
_pytorch_storage_protocol0_persistent_id_payload = cast(
    _StorageProtocol0Payload, _fixtures._pytorch_storage_protocol0_persistent_id_payload
)
_pytorch_storage_then_arbitrary_protocol0_persistent_id_payload = cast(
    Callable[[str], bytes], _fixtures._pytorch_storage_then_arbitrary_protocol0_persistent_id_payload
)
_require_torch_distribution = cast(Callable[[], None], _fixtures._require_torch_distribution)
_shadow_framework_divergence_cases = cast(
    Callable[[], tuple[object, ...]], _fixtures._shadow_framework_divergence_cases
)
_shadow_newobj_build_payload = cast(_ShadowBuildPayload, _fixtures._shadow_newobj_build_payload)
_shadow_slot_state_build_payload = cast(Callable[[], bytes], _fixtures._shadow_slot_state_build_payload)
pickle_short_binunicode = cast(Callable[[bytes], bytes], _fixtures._short_binunicode)
_static_getattr_protocol0_unicode_payload = cast(
    Callable[[], bytes], _fixtures._static_getattr_protocol0_unicode_payload
)
_yolov5n6_tensor_storage_prefix_bytes = cast(Callable[[], bytes], _fixtures._yolov5n6_tensor_storage_prefix_bytes)
_replace_source_on_read = cast(
    "Callable[[pytest.MonkeyPatch, Path, Path, Path], None]", _fixtures._replace_source_on_read
)
_replace_source_after_fstat = cast(
    "Callable[[pytest.MonkeyPatch, Path, Path, Path], None]", _fixtures._replace_source_after_fstat
)
