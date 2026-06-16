"""Scanner for NVIDIA NeMo model files (.nemo).

NeMo files are tar archives containing YAML configuration and model weights.
CVE-2025-23304: Hydra _target_ fields in NeMo configs can specify arbitrary
Python callables, enabling RCE when loaded via hydra.utils.instantiate().
"""

import logging
import os
import posixpath
import re
import tarfile
import tempfile
from collections.abc import Iterator
from typing import Any, BinaryIO, ClassVar

from ..core_results import (
    OPERATIONAL_ERROR_REASON_METADATA_KEY,
    mark_operational_scan_error,
    metadata_has_incomplete_coverage,
    record_details_have_incomplete_coverage,
    records_have_incomplete_coverage,
    scan_result_has_operational_error,
)
from ..utils import is_absolute_archive_path, sanitize_archive_path
from ..utils.file.detection import is_nemo_archive
from ._archive_locations import rewrite_extracted_member_location
from ._archive_outcomes import mark_archive_scan_incomplete
from ._evidence_redaction import redact_evidence_string
from .archive_member_security import (
    is_executable_archive_member_name,
    is_python_archive_member_name,
    scan_archive_member_for_known_risks,
)
from .base import INCONCLUSIVE_SCAN_OUTCOME, BaseScanner, CheckStatus, IssueSeverity, ScanResult
from .tar_scanner import (
    TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY,
    TAR_SKIP_REACHABLE_NEMO_CONFIG_SCAN_KEY,
    TarScanner,
    _tar_shared_scan_budget_exhausted,
    _tar_shared_scan_budget_scope,
)

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_PREFLIGHT_PREFIX_ANALYSIS_REASONS = frozenset(
    {
        "tar_metadata_read_limit_exceeded",
        "tar_total_size_limit_exceeded",
    }
)

# Safe _target_ prefixes that are expected in legitimate NeMo configs
_SAFE_TARGET_PREFIXES = (
    "nemo.",
    "nemo_toolkit.",
    "pytorch_lightning.",
    "lightning.",
    "torch.optim.",
    "torch.nn.",
    "transformers.",
    "omegaconf.",
    "hydra.",
    "megatron.",
    "apex.",
    "numpy.",
    "dataclasses.",
)

# Exact safe _target_ values for utility namespaces that also contain unsafe
# callables. Keep this list narrow instead of trusting whole namespaces.
_SAFE_TARGETS = {
    "transformers.utils.PushToHubMixin.save_pretrained",
    "transformers.utils.hub.PushToHubMixin.save_pretrained",
    "torch.utils.data.BatchSampler",
    "torch.utils.data.ConcatDataset",
    "torch.utils.data.DataLoader",
    "torch.utils.data.RandomSampler",
    "torch.utils.data.SequentialSampler",
    "torch.utils.data.Subset",
    "torch.utils.data.TensorDataset",
    "torch.utils.data.WeightedRandomSampler",
    "torch.utils.data.distributed.DistributedSampler",
    "torch.utils.data.dataloader.DataLoader",
    "torch.utils.data.dataset.ConcatDataset",
    "torch.utils.data.dataset.Subset",
    "torch.utils.data.dataset.TensorDataset",
    "torch.utils.data.sampler.BatchSampler",
    "torch.utils.data.sampler.RandomSampler",
    "torch.utils.data.sampler.SequentialSampler",
    "torch.utils.data.sampler.WeightedRandomSampler",
}

# Dangerous _target_ values that indicate exploitation
_DANGEROUS_TARGETS = {
    "os.system",
    "os.popen",
    "os.exec",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "posix.execv",
    "posix.execve",
    "nt.execv",
    "nt.execve",
    "os.spawn",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "nt.spawnv",
    "nt.spawnve",
    "os.posix_spawn",
    "os.posix_spawnp",
    "os.fork",
    "posix.fork",
    "os.forkpty",
    "posix.forkpty",
    "pty.fork",
    "os.kill",
    "posix.kill",
    "nt.kill",
    "os.killpg",
    "posix.killpg",
    "signal.raise_signal",
    "signal.pthread_kill",
    "signal.alarm",
    "signal.setitimer",
    "signal.signal",
    "sys.exit",
    "os.abort",
    "posix.abort",
    "nt.abort",
    "os._exit",
    "posix._exit",
    "nt._exit",
    "posix.system",
    "posix.posix_spawn",
    "posix.posix_spawnp",
    "nt.system",
    "os.startfile",
    "nt.startfile",
    "runpy.run_module",
    "runpy.run_path",
    "operator.call",
    "asyncio.run",
    "threading.Thread.start",
    "multiprocessing.Process.start",
    "multiprocessing.Pool",
    "multiprocessing.pool.Pool",
    "multiprocessing.Manager",
    "multiprocessing.connection.Client",
    "multiprocessing.connection.Listener",
    "multiprocessing.managers.BaseManager.start",
    "multiprocessing.managers.SyncManager.start",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "builtins.eval",
    "builtins.exec",
    "builtins.__import__",
    "hydra.compose",
    "hydra.compose.compose",
    "hydra.experimental.compose",
    "hydra.experimental.initialize",
    "hydra.experimental.initialize_config_dir",
    "hydra.experimental.initialize_config_module",
    "hydra.initialize",
    "hydra.initialize.initialize",
    "hydra.initialize.initialize_config_dir",
    "hydra.initialize.initialize_config_module",
    "hydra.initialize_config_dir",
    "hydra.initialize_config_module",
    "hydra.core.config_store.ConfigStore.store",
    "hydra.core.config_store.ConfigStoreWithProvider.store",
    "hydra.core.global_hydra.GlobalHydra.clear",
    "hydra.core.global_hydra.GlobalHydra.initialize",
    "hydra.core.global_hydra.GlobalHydra.set_instance",
    "hydra.core.utils._save_config",
    "hydra.core.utils.configure_log",
    "hydra.core.utils.run_job",
    "importlib.import_module",
    "hydra._internal.utils._locate",
    "hydra.utils._locate",
    "hydra.utils.get_class",
    "hydra.utils.get_method",
    "hydra.utils.get_object",
    "hydra.utils.get_static_method",
    "importlib.machinery.SourceFileLoader.load_module",
    "importlib.machinery.SourceFileLoader.exec_module",
    "importlib.machinery.SourcelessFileLoader.load_module",
    "importlib.machinery.SourcelessFileLoader.exec_module",
    "importlib.machinery.ExtensionFileLoader.load_module",
    "importlib.machinery.ExtensionFileLoader.exec_module",
    "zipimport.zipimporter.load_module",
    "zipimport.zipimporter.exec_module",
    "pydoc.importfile",
    "logging.config.dictConfig",
    "logging.config.fileConfig",
    "site.addpackage",
    "site.addsitedir",
    "site.execsitecustomize",
    "site.execusercustomize",
    "site.main",
    "builtins.open",
    "io.open",
    "_io.open",
    "io.open_code",
    "_io.open_code",
    "io.FileIO",
    "_io.FileIO",
    "codecs.open",
    "configparser.ConfigParser.read",
    "configparser.RawConfigParser.read",
    "filecmp.cmp",
    "filecmp.cmpfiles",
    "linecache.checkcache",
    "linecache.getline",
    "linecache.getlines",
    "linecache.updatecache",
    "logging.FileHandler",
    "logging.handlers.BaseRotatingHandler",
    "logging.handlers.RotatingFileHandler",
    "logging.handlers.SysLogHandler",
    "logging.handlers.TimedRotatingFileHandler",
    "logging.handlers.WatchedFileHandler",
    "omegaconf.OmegaConf.load",
    "omegaconf.OmegaConf.save",
    "omegaconf.OmegaConf.clear_resolver",
    "omegaconf.OmegaConf.clear_resolvers",
    "omegaconf.OmegaConf.legacy_register_resolver",
    "omegaconf.OmegaConf.register_new_resolver",
    "omegaconf.OmegaConf.register_resolver",
    "omegaconf.omegaconf.OmegaConf.load",
    "omegaconf.omegaconf.OmegaConf.save",
    "omegaconf.omegaconf.OmegaConf.clear_resolver",
    "omegaconf.omegaconf.OmegaConf.clear_resolvers",
    "omegaconf.omegaconf.OmegaConf.legacy_register_resolver",
    "omegaconf.omegaconf.OmegaConf.register_new_resolver",
    "omegaconf.omegaconf.OmegaConf.register_resolver",
    "tokenize.open",
    "bz2.BZ2File",
    "bz2.open",
    "dbm.open",
    "gzip.GzipFile",
    "gzip.open",
    "lzma.LZMAFile",
    "lzma.open",
    "shelve.open",
    "sqlite3.Connection",
    "sqlite3.connect",
    "tarfile.TarFile",
    "tarfile.TarFile.extract",
    "tarfile.TarFile.extractall",
    "tarfile.TarFile.open",
    "tarfile.open",
    "tempfile.NamedTemporaryFile",
    "tempfile.TemporaryDirectory",
    "tempfile.TemporaryFile",
    "tempfile.mkdtemp",
    "tempfile.mkstemp",
    "tempfile.mktemp",
    "zipfile.Path",
    "zipfile.PyZipFile",
    "zipfile.ZipFile",
    "zipfile.ZipFile.extract",
    "zipfile.ZipFile.extractall",
    "pickle.loads",
    "pickle.load",
    "cloudpickle.loads",
    "cloudpickle.load",
    "dill.loads",
    "dill.load",
    "joblib.load",
    "sklearn.externals.joblib.load",
    "keras.models.load_model",
    "mlflow.pyfunc.load_model",
    "pandas.read_pickle",
    "tensorflow.keras.models.load_model",
    "tensorflow.saved_model.load",
    "tf.keras.models.load_model",
    "torch.hub.load",
    "torch.hub.load_state_dict_from_url",
    "torch.jit.load",
    "torch.load",
    "torch.package.PackageImporter",
    "torch.package.PackageImporter.load_pickle",
    "torch.save",
    "torch.serialization.load",
    "torch.serialization.save",
    "torch.classes.load_library",
    "torch.ops.load_library",
    "torch.utils.cpp_extension._import_module_from_library",
    "torch.utils.cpp_extension._jit_compile",
    "torch.utils.cpp_extension._run_ninja_build",
    "torch.utils.cpp_extension.load",
    "torch.utils.cpp_extension.load_inline",
    "torch.utils.model_zoo.load_url",
    "transformers.pipeline",
    "transformers.dynamic_module_utils._compute_local_source_files_hash",
    "transformers.dynamic_module_utils.check_imports",
    "transformers.dynamic_module_utils.check_python_requirements",
    "transformers.dynamic_module_utils.create_dynamic_module",
    "transformers.dynamic_module_utils.custom_object_save",
    "transformers.dynamic_module_utils.get_cached_module_file",
    "transformers.dynamic_module_utils.get_class_from_dynamic_module",
    "transformers.dynamic_module_utils.get_class_in_module",
    "transformers.dynamic_module_utils.get_imports",
    "transformers.dynamic_module_utils.get_relative_import_files",
    "transformers.dynamic_module_utils.get_relative_imports",
    "transformers.dynamic_module_utils.init_hf_modules",
    "transformers.dynamic_module_utils.resolve_trust_remote_code",
    "transformers.pipelines.audio_classification.ffmpeg_read",
    "transformers.pipelines.audio_utils.ffmpeg_read",
    "transformers.testing_utils.run_command",
    "transformers.utils.cached_file",
    "transformers.utils.hub.PushToHubMixin._create_repo",
    "transformers.utils.hub.PushToHubMixin._upload_modified_files",
    "transformers.utils.hub.cached_file",
    "transformers.utils.hub.cached_files",
    "transformers.utils.hub.create_branch",
    "transformers.utils.hub.create_commit",
    "transformers.utils.hub.create_repo",
    "transformers.utils.hub.create_and_tag_model_card",
    "transformers.utils.hub.define_sagemaker_information",
    "transformers.utils.hub.download_url",
    "transformers.utils.hub.get_file_from_repo",
    "transformers.utils.hub.get_checkpoint_shard_files",
    "transformers.utils.hub.has_file",
    "transformers.utils.hub.hf_hub_download",
    "transformers.utils.hub.http_get",
    "transformers.utils.hub.httpx.get",
    "transformers.utils.hub.list_repo_templates",
    "transformers.utils.hub.list_repo_tree",
    "transformers.utils.hub.requests.get",
    "transformers.utils.hub.snapshot_download",
    "transformers.utils.import_utils._LazyModule._get_module",
    "transformers.utils.import_utils.clear_import_cache",
    "transformers.utils.import_utils.create_import_structure_from_path",
    "transformers.utils.import_utils.define_import_structure",
    "transformers.utils.import_utils.direct_transformers_import",
    "tensorflow.load_op_library",
    "numpy.fromfile",
    "numpy.fromregex",
    "numpy.genfromtxt",
    "numpy.lib._datasource.DataSource._cache",
    "numpy.lib._datasource.DataSource._findfile",
    "numpy.lib._datasource.DataSource.exists",
    "numpy.lib._datasource.DataSource.open",
    "numpy.lib._datasource.open",
    "numpy.lib._format_impl.open_memmap",
    "numpy.lib._npyio_impl.fromregex",
    "numpy.lib._npyio_impl.genfromtxt",
    "numpy.lib._npyio_impl.load",
    "numpy.lib._npyio_impl.loadtxt",
    "numpy.lib._npyio_impl.NpzFile",
    "numpy.lib._npyio_impl.save",
    "numpy.lib._npyio_impl.savez",
    "numpy.lib._npyio_impl.savez_compressed",
    "numpy.lib._npyio_impl.savetxt",
    "numpy.lib.format.open_memmap",
    "numpy.lib.npyio.DataSource._cache",
    "numpy.lib.npyio.DataSource._findfile",
    "numpy.lib.npyio.DataSource.exists",
    "numpy.lib.npyio.DataSource.open",
    "numpy.lib.npyio.fromregex",
    "numpy.lib.npyio.genfromtxt",
    "numpy.lib.npyio.load",
    "numpy.lib.npyio.loadtxt",
    "numpy.lib.npyio.NpzFile",
    "numpy.lib.npyio.recfromcsv",
    "numpy.lib.npyio.recfromtxt",
    "numpy.lib.npyio.save",
    "numpy.lib.npyio.savez",
    "numpy.lib.npyio.savez_compressed",
    "numpy.lib.npyio.savetxt",
    "numpy.load",
    "numpy.loadtxt",
    "numpy.memmap",
    "numpy._core.memmap.memmap",
    "numpy._core.multiarray.fromfile",
    "numpy._core.records.fromfile",
    "numpy.core.memmap.memmap",
    "numpy.core.multiarray.fromfile",
    "numpy.core.records.fromfile",
    "numpy.ndarray.dump",
    "numpy.ndarray.tofile",
    "numpy.rec.fromfile",
    "numpy.recfromcsv",
    "numpy.recfromtxt",
    "numpy.distutils.exec_command._exec_command",
    "numpy.distutils.exec_command.exec_command",
    "numpy.save",
    "numpy.savez",
    "numpy.savez_compressed",
    "numpy.savetxt",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "requests.request",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.api.request",
    "requests.api.get",
    "requests.api.post",
    "requests.api.put",
    "requests.api.patch",
    "requests.api.delete",
    "requests.api.head",
    "requests.api.options",
    "requests.Session.request",
    "requests.Session.get",
    "requests.Session.post",
    "requests.Session.put",
    "requests.Session.patch",
    "requests.Session.delete",
    "requests.Session.head",
    "requests.Session.options",
    "requests.Session.send",
    "requests.sessions.Session.request",
    "requests.sessions.Session.get",
    "requests.sessions.Session.post",
    "requests.sessions.Session.put",
    "requests.sessions.Session.patch",
    "requests.sessions.Session.delete",
    "requests.sessions.Session.head",
    "requests.sessions.Session.options",
    "requests.sessions.Session.send",
    "httpx.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.options",
    "httpx._api.request",
    "httpx._api.get",
    "httpx._api.post",
    "httpx._api.put",
    "httpx._api.patch",
    "httpx._api.delete",
    "httpx._api.head",
    "httpx._api.options",
    "httpx.Client.request",
    "httpx.Client.get",
    "httpx.Client.post",
    "httpx.Client.put",
    "httpx.Client.patch",
    "httpx.Client.delete",
    "httpx.Client.head",
    "httpx.Client.options",
    "httpx.Client.send",
    "httpx._client.Client.request",
    "httpx._client.Client.get",
    "httpx._client.Client.post",
    "httpx._client.Client.put",
    "httpx._client.Client.patch",
    "httpx._client.Client.delete",
    "httpx._client.Client.head",
    "httpx._client.Client.options",
    "httpx._client.Client.send",
    "urllib3.request",
    "urllib3.HTTPConnectionPool.request",
    "urllib3.HTTPConnectionPool.urlopen",
    "urllib3.HTTPSConnectionPool.request",
    "urllib3.HTTPSConnectionPool.urlopen",
    "urllib3.PoolManager.request",
    "urllib3.PoolManager.urlopen",
    "urllib3.ProxyManager.request",
    "urllib3.ProxyManager.urlopen",
    "urllib3.poolmanager.PoolManager.request",
    "urllib3.poolmanager.PoolManager.urlopen",
    "urllib3.poolmanager.ProxyManager.request",
    "urllib3.poolmanager.ProxyManager.urlopen",
    "urllib3.connectionpool.HTTPConnectionPool.request",
    "urllib3.connectionpool.HTTPConnectionPool.urlopen",
    "urllib3.connectionpool.HTTPSConnectionPool.request",
    "urllib3.connectionpool.HTTPSConnectionPool.urlopen",
    "urllib3._request_methods.RequestMethods.request",
    "urllib.request.OpenerDirector.open",
    "urllib.request.URLopener.open",
    "urllib.request.URLopener.open_file",
    "urllib.request.URLopener.open_ftp",
    "urllib.request.URLopener.open_http",
    "urllib.request.URLopener.open_https",
    "urllib.request.URLopener.open_local_file",
    "urllib.request.URLopener.retrieve",
    "urllib.request.FancyURLopener.open",
    "urllib.request.FancyURLopener.open_file",
    "urllib.request.FancyURLopener.open_ftp",
    "urllib.request.FancyURLopener.open_http",
    "urllib.request.FancyURLopener.open_https",
    "urllib.request.FancyURLopener.open_local_file",
    "urllib.request.FancyURLopener.retrieve",
    "ftplib.FTP",
    "ftplib.FTP_TLS",
    "ftplib.FTP.connect",
    "ftplib.FTP_TLS.connect",
    "imaplib.IMAP4",
    "imaplib.IMAP4_SSL",
    "imaplib.IMAP4.open",
    "imaplib.IMAP4_SSL.open",
    "nntplib.NNTP",
    "nntplib.NNTP_SSL",
    "poplib.POP3",
    "poplib.POP3_SSL",
    "smtplib.LMTP",
    "smtplib.LMTP.connect",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "smtplib.SMTP.connect",
    "smtplib.SMTP_SSL.connect",
    "telnetlib.Telnet",
    "nntplib.NNTP._create_socket",
    "nntplib.NNTP_SSL._create_socket",
    "poplib.POP3._create_socket",
    "poplib.POP3_SSL._create_socket",
    "telnetlib.Telnet.open",
    "http.client.HTTPConnection.request",
    "http.client.HTTPSConnection.request",
    "http.client.HTTPConnection.connect",
    "http.client.HTTPSConnection.connect",
    "http.client.HTTPConnection.send",
    "http.client.HTTPSConnection.send",
    "http.client.HTTPConnection.getresponse",
    "http.client.HTTPSConnection.getresponse",
    "http.client.HTTPConnection.endheaders",
    "http.client.HTTPSConnection.endheaders",
    "http.client.HTTPConnection._send_output",
    "http.client.HTTPSConnection._send_output",
    "http.client.HTTPResponse.read",
    "http.client.HTTPResponse.read1",
    "http.client.HTTPResponse.readinto",
    "http.client.HTTPResponse.readinto1",
    "http.client.HTTPResponse.readline",
    "http.client.HTTPResponse.readlines",
    "http.client.HTTPResponse.peek",
    "socket.create_connection",
    "socket.create_server",
    "socketserver.TCPServer",
    "socketserver.UDPServer",
    "socketserver.ThreadingTCPServer",
    "socketserver.ThreadingUDPServer",
    "http.server.HTTPServer",
    "http.server.ThreadingHTTPServer",
    "wsgiref.simple_server.WSGIServer",
    "wsgiref.simple_server.make_server",
    "socket.getaddrinfo",
    "socket.getfqdn",
    "socket.gethostbyaddr",
    "socket.gethostbyname",
    "socket.gethostbyname_ex",
    "socket.getnameinfo",
    "socket.socket.connect",
    "socket.socket.connect_ex",
    "socket.socket.bind",
    "socket.socket.listen",
    "socket.socket.accept",
    "socket.socket.send",
    "socket.socket.sendall",
    "socket.socket.sendfile",
    "socket.socket.sendto",
    "socket.socket.sendmsg",
    "socket.socket.recv",
    "socket.socket.recvfrom",
    "socket.socket.recv_into",
    "socket.socket.recvfrom_into",
    "socket.socket.recvmsg",
    "socket.socket.recvmsg_into",
    "socket.SocketType.connect",
    "socket.SocketType.connect_ex",
    "socket.SocketType.bind",
    "socket.SocketType.listen",
    "socket.SocketType.accept",
    "socket.SocketType.send",
    "socket.SocketType.sendall",
    "socket.SocketType.sendfile",
    "socket.SocketType.sendto",
    "socket.SocketType.sendmsg",
    "socket.SocketType.recv",
    "socket.SocketType.recvfrom",
    "socket.SocketType.recv_into",
    "socket.SocketType.recvfrom_into",
    "socket.SocketType.recvmsg",
    "socket.SocketType.recvmsg_into",
    "socket.send_fds",
    "socket.recv_fds",
    "_socket.socket.connect",
    "_socket.socket.connect_ex",
    "_socket.socket.bind",
    "_socket.socket.listen",
    "_socket.socket.accept",
    "_socket.socket.send",
    "_socket.socket.sendall",
    "_socket.socket.sendto",
    "_socket.socket.sendmsg",
    "_socket.socket.recv",
    "_socket.socket.recvfrom",
    "_socket.socket.recv_into",
    "_socket.socket.recvfrom_into",
    "_socket.socket.recvmsg",
    "_socket.socket.recvmsg_into",
    "_socket.SocketType.connect",
    "_socket.SocketType.connect_ex",
    "_socket.SocketType.bind",
    "_socket.SocketType.listen",
    "_socket.SocketType.accept",
    "_socket.SocketType.send",
    "_socket.SocketType.sendall",
    "_socket.SocketType.sendto",
    "_socket.SocketType.sendmsg",
    "_socket.SocketType.recv",
    "_socket.SocketType.recvfrom",
    "_socket.SocketType.recv_into",
    "_socket.SocketType.recvfrom_into",
    "_socket.SocketType.recvmsg",
    "_socket.SocketType.recvmsg_into",
    "_socket.getaddrinfo",
    "_socket.gethostbyaddr",
    "_socket.gethostbyname",
    "_socket.gethostbyname_ex",
    "_socket.getnameinfo",
    "socket.socket",
    "socket.SocketType",
    "socket.socketpair",
    "_socket.socket",
    "_socket.SocketType",
    "_socket.socketpair",
    "os.pipe",
    "posix.pipe",
    "nt.pipe",
    "os.pipe2",
    "posix.pipe2",
    "nt.pipe2",
    "os.open",
    "posix.open",
    "nt.open",
    "os.read",
    "posix.read",
    "nt.read",
    "os.readv",
    "posix.readv",
    "os.pread",
    "posix.pread",
    "os.preadv",
    "posix.preadv",
    "os.write",
    "posix.write",
    "nt.write",
    "os.close",
    "posix.close",
    "nt.close",
    "os.closerange",
    "posix.closerange",
    "nt.closerange",
    "os.dup",
    "posix.dup",
    "nt.dup",
    "os.dup2",
    "posix.dup2",
    "nt.dup2",
    "os.writev",
    "posix.writev",
    "os.pwrite",
    "posix.pwrite",
    "os.pwritev",
    "posix.pwritev",
    "os.sendfile",
    "posix.sendfile",
    "os.copy_file_range",
    "posix.copy_file_range",
    "os.splice",
    "posix.splice",
    "os.readlink",
    "posix.readlink",
    "nt.readlink",
    "os.listdir",
    "posix.listdir",
    "nt.listdir",
    "os.scandir",
    "posix.scandir",
    "nt.scandir",
    "os.chdir",
    "posix.chdir",
    "nt.chdir",
    "os.fchdir",
    "posix.fchdir",
    "os.umask",
    "posix.umask",
    "nt.umask",
    "os.chroot",
    "posix.chroot",
    "os.setuid",
    "posix.setuid",
    "os.seteuid",
    "posix.seteuid",
    "os.setgid",
    "posix.setgid",
    "os.setegid",
    "posix.setegid",
    "os.setreuid",
    "posix.setreuid",
    "os.setregid",
    "posix.setregid",
    "os.setresuid",
    "posix.setresuid",
    "os.setresgid",
    "posix.setresgid",
    "os.setgroups",
    "posix.setgroups",
    "os.initgroups",
    "posix.initgroups",
    "os.setsid",
    "posix.setsid",
    "os.setpgid",
    "posix.setpgid",
    "os.setpgrp",
    "posix.setpgrp",
    "os.tcsetpgrp",
    "posix.tcsetpgrp",
    "os.putenv",
    "posix.putenv",
    "nt.putenv",
    "os.unsetenv",
    "posix.unsetenv",
    "nt.unsetenv",
    "os.environ.clear",
    "os.environ.pop",
    "os.environ.popitem",
    "os.environ.setdefault",
    "os.environ.update",
    "os.environ.__setitem__",
    "os.environ.__delitem__",
    "os.environ.__ior__",
    "os.environb.clear",
    "os.environb.pop",
    "os.environb.popitem",
    "os.environb.setdefault",
    "os.environb.update",
    "os.environb.__setitem__",
    "os.environb.__delitem__",
    "os.environb.__ior__",
    "sys.path.append",
    "sys.path.clear",
    "sys.path.extend",
    "sys.path.insert",
    "sys.path.pop",
    "sys.path.remove",
    "sys.path.reverse",
    "sys.path.sort",
    "sys.path.__setitem__",
    "sys.path.__delitem__",
    "sys.path.__iadd__",
    "sys.path.__imul__",
    "sys.modules.clear",
    "sys.modules.pop",
    "sys.modules.popitem",
    "sys.modules.setdefault",
    "sys.modules.update",
    "sys.modules.__setitem__",
    "sys.modules.__delitem__",
    "sys.modules.__ior__",
    "resource.setrlimit",
    "resource.prlimit",
    "os.stat",
    "os.access",
    "os.fstat",
    "os.statvfs",
    "os.fstatvfs",
    "os.path.exists",
    "os.path.lexists",
    "os.path.isfile",
    "os.path.isdir",
    "os.path.islink",
    "os.path.ismount",
    "os.path.getatime",
    "os.path.getctime",
    "os.path.getmtime",
    "os.path.getsize",
    "os.path.realpath",
    "os.path.samefile",
    "os.path.sameopenfile",
    "posix.stat",
    "posix.access",
    "posix.fstat",
    "posix.statvfs",
    "posix.fstatvfs",
    "posixpath.exists",
    "posixpath.lexists",
    "posixpath.isfile",
    "posixpath.isdir",
    "posixpath.islink",
    "posixpath.ismount",
    "posixpath.getatime",
    "posixpath.getctime",
    "posixpath.getmtime",
    "posixpath.getsize",
    "posixpath.realpath",
    "posixpath.samefile",
    "posixpath.sameopenfile",
    "nt.stat",
    "nt.access",
    "nt.fstat",
    "ntpath.exists",
    "ntpath.lexists",
    "ntpath.isfile",
    "ntpath.isdir",
    "ntpath.islink",
    "ntpath.ismount",
    "ntpath.getatime",
    "ntpath.getctime",
    "ntpath.getmtime",
    "ntpath.getsize",
    "ntpath.realpath",
    "ntpath.samefile",
    "ntpath.sameopenfile",
    "genericpath.exists",
    "genericpath.isfile",
    "genericpath.isdir",
    "genericpath.getatime",
    "genericpath.getctime",
    "genericpath.getmtime",
    "genericpath.getsize",
    "genericpath.samefile",
    "genericpath.sameopenfile",
    "os.lstat",
    "posix.lstat",
    "nt.lstat",
    "glob.glob",
    "os.mkdir",
    "posix.mkdir",
    "nt.mkdir",
    "os.makedirs",
    "pathlib.Path.open",
    "pathlib.PosixPath.open",
    "pathlib.WindowsPath.open",
    "pathlib.Path.mkdir",
    "pathlib.PosixPath.mkdir",
    "pathlib.WindowsPath.mkdir",
    "pathlib.Path.touch",
    "pathlib.PosixPath.touch",
    "pathlib.WindowsPath.touch",
    "pathlib.Path.read_bytes",
    "pathlib.PosixPath.read_bytes",
    "pathlib.WindowsPath.read_bytes",
    "pathlib.Path.read_text",
    "pathlib.PosixPath.read_text",
    "pathlib.WindowsPath.read_text",
    "pathlib.Path.readlink",
    "pathlib.PosixPath.readlink",
    "pathlib.WindowsPath.readlink",
    "pathlib.Path.iterdir",
    "pathlib.PosixPath.iterdir",
    "pathlib.WindowsPath.iterdir",
    "pathlib.Path.stat",
    "pathlib.Path.exists",
    "pathlib.Path.is_file",
    "pathlib.Path.is_dir",
    "pathlib.Path.is_symlink",
    "pathlib.Path.is_mount",
    "pathlib.Path.is_socket",
    "pathlib.Path.is_fifo",
    "pathlib.Path.is_block_device",
    "pathlib.Path.is_char_device",
    "pathlib.PosixPath.stat",
    "pathlib.PosixPath.exists",
    "pathlib.PosixPath.is_file",
    "pathlib.PosixPath.is_dir",
    "pathlib.PosixPath.is_symlink",
    "pathlib.PosixPath.is_mount",
    "pathlib.PosixPath.is_socket",
    "pathlib.PosixPath.is_fifo",
    "pathlib.PosixPath.is_block_device",
    "pathlib.PosixPath.is_char_device",
    "pathlib.WindowsPath.stat",
    "pathlib.WindowsPath.exists",
    "pathlib.WindowsPath.is_file",
    "pathlib.WindowsPath.is_dir",
    "pathlib.WindowsPath.is_symlink",
    "pathlib.WindowsPath.is_mount",
    "pathlib.WindowsPath.is_socket",
    "pathlib.WindowsPath.is_fifo",
    "pathlib.WindowsPath.is_block_device",
    "pathlib.WindowsPath.is_char_device",
    "pathlib.Path.lstat",
    "pathlib.PosixPath.lstat",
    "pathlib.WindowsPath.lstat",
    "pathlib.Path.resolve",
    "pathlib.PosixPath.resolve",
    "pathlib.WindowsPath.resolve",
    "pathlib.Path.samefile",
    "pathlib.PosixPath.samefile",
    "pathlib.WindowsPath.samefile",
    "pathlib.Path.owner",
    "pathlib.PosixPath.owner",
    "pathlib.WindowsPath.owner",
    "pathlib.Path.group",
    "pathlib.PosixPath.group",
    "pathlib.WindowsPath.group",
    "pathlib.Path.write_bytes",
    "pathlib.PosixPath.write_bytes",
    "pathlib.WindowsPath.write_bytes",
    "pathlib.Path.write_text",
    "pathlib.PosixPath.write_text",
    "pathlib.WindowsPath.write_text",
    "os.remove",
    "posix.remove",
    "nt.remove",
    "os.unlink",
    "posix.unlink",
    "nt.unlink",
    "os.rename",
    "posix.rename",
    "nt.rename",
    "os.renames",
    "os.replace",
    "posix.replace",
    "nt.replace",
    "os.rmdir",
    "posix.rmdir",
    "nt.rmdir",
    "os.removedirs",
    "os.symlink",
    "posix.symlink",
    "nt.symlink",
    "os.link",
    "posix.link",
    "nt.link",
    "os.truncate",
    "posix.truncate",
    "nt.truncate",
    "os.ftruncate",
    "posix.ftruncate",
    "nt.ftruncate",
    "os.fsync",
    "posix.fsync",
    "nt.fsync",
    "os.fdatasync",
    "posix.fdatasync",
    "os.chmod",
    "posix.chmod",
    "nt.chmod",
    "os.fchmod",
    "posix.fchmod",
    "nt.fchmod",
    "os.chown",
    "posix.chown",
    "os.fchown",
    "posix.fchown",
    "os.lchown",
    "posix.lchown",
    "os.utime",
    "posix.utime",
    "nt.utime",
    "os.mknod",
    "posix.mknod",
    "os.mkfifo",
    "posix.mkfifo",
    "os.getxattr",
    "posix.getxattr",
    "os.listxattr",
    "posix.listxattr",
    "os.setxattr",
    "posix.setxattr",
    "os.removexattr",
    "posix.removexattr",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copyfileobj",
    "shutil.copytree",
    "shutil.copymode",
    "shutil.copystat",
    "shutil.chown",
    "shutil.disk_usage",
    "shutil.which",
    "shutil.make_archive",
    "shutil.move",
    "shutil.rmtree",
    "shutil.unpack_archive",
    "pathlib.Path.chmod",
    "pathlib.PosixPath.chmod",
    "pathlib.WindowsPath.chmod",
    "pathlib.Path.lchmod",
    "pathlib.PosixPath.lchmod",
    "pathlib.WindowsPath.lchmod",
    "pathlib.Path.unlink",
    "pathlib.PosixPath.unlink",
    "pathlib.WindowsPath.unlink",
    "pathlib.Path.rename",
    "pathlib.PosixPath.rename",
    "pathlib.WindowsPath.rename",
    "pathlib.Path.replace",
    "pathlib.PosixPath.replace",
    "pathlib.WindowsPath.replace",
    "pathlib.Path.rmdir",
    "pathlib.PosixPath.rmdir",
    "pathlib.WindowsPath.rmdir",
    "pathlib.Path.symlink_to",
    "pathlib.PosixPath.symlink_to",
    "pathlib.WindowsPath.symlink_to",
    "pathlib.Path.hardlink_to",
    "pathlib.PosixPath.hardlink_to",
    "pathlib.WindowsPath.hardlink_to",
    "pathlib.Path.link_to",
    "pathlib.PosixPath.link_to",
    "pathlib.WindowsPath.link_to",
    "webbrowser.open",
    "webbrowser.open_new",
    "webbrowser.open_new_tab",
    "ssl.create_default_context",
    "ssl.SSLContext.load_cert_chain",
    "ssl.SSLContext.load_verify_locations",
    "importlib.resources.open_binary",
    "importlib.resources.open_text",
    "importlib.resources.read_binary",
    "importlib.resources.read_text",
    "pkgutil.get_data",
    "os.add_dll_directory",
    "nt.add_dll_directory",
    "_ctypes.dlopen",
    "ctypes.CDLL",
    "ctypes.OleDLL",
    "ctypes.PyDLL",
    "ctypes.WinDLL",
    "ctypes._dlopen",
    "ctypes.cdll.LoadLibrary",
    "ctypes.oledll.LoadLibrary",
    "ctypes.pydll.LoadLibrary",
    "ctypes.windll.LoadLibrary",
    "ctypes.pythonapi.PyRun_AnyFile",
    "ctypes.pythonapi.PyRun_AnyFileEx",
    "ctypes.pythonapi.PyRun_AnyFileExFlags",
    "ctypes.pythonapi.PyRun_AnyFileFlags",
    "ctypes.pythonapi.PyRun_File",
    "ctypes.pythonapi.PyRun_FileEx",
    "ctypes.pythonapi.PyRun_FileExFlags",
    "ctypes.pythonapi.PyRun_FileFlags",
    "ctypes.pythonapi.PyRun_InteractiveLoop",
    "ctypes.pythonapi.PyRun_InteractiveLoopFlags",
    "ctypes.pythonapi.PyRun_InteractiveOne",
    "ctypes.pythonapi.PyRun_InteractiveOneFlags",
    "ctypes.pythonapi.PyRun_SimpleFile",
    "ctypes.pythonapi.PyRun_SimpleFileEx",
    "ctypes.pythonapi.PyRun_SimpleFileExFlags",
    "ctypes.pythonapi.PyRun_SimpleString",
    "ctypes.pythonapi.PyRun_SimpleStringFlags",
    "ctypes.pythonapi.PyRun_String",
    "ctypes.pythonapi.PyRun_StringFlags",
    "ctypes.util.find_library",
    "numpy.ctypeslib.load_library",
    "code.interact",
    "pty.spawn",
}
_DANGEROUS_TARGET_PREFIXES = (
    "ctypes.cdll.",
    "ctypes.oledll.",
    "ctypes.pydll.",
    "ctypes.windll.",
)
_DANGEROUS_NUMPY_TARGET_SUFFIXES = (".dump", ".tofile")
_DANGEROUS_TRANSFORMERS_TARGET_SUFFIXES = (".from_pretrained", ".push_to_hub", ".save_pretrained")
_TARGET_CALL_ALIAS_SUFFIX = ".__call__"
_HYDRA_DYNAMIC_CONFIG_TARGETS = frozenset(
    {
        "hydra.utils.call",
        "hydra.utils.instantiate",
        "hydra.experimental.call",
        "hydra.experimental.instantiate",
    }
)
_MODEL_LOAD_ARGUMENT_KEYS_BY_SUFFIX = {
    ".load_from_checkpoint": frozenset({"checkpoint_path", "hparams_file"}),
    ".restore_from": frozenset({"override_config_path", "restore_path"}),
    ".from_pretrained": frozenset(
        {"model_name", "model_name_or_path", "override_config_path", "pretrained_model_name_or_path"}
    ),
}
_MODEL_LOAD_POSITIONAL_ARGUMENTS_BY_SUFFIX = {
    ".load_from_checkpoint": ("checkpoint_path", None, "hparams_file"),
    ".restore_from": ("restore_path", "override_config_path"),
    ".from_pretrained": ("model_name", None, "override_config_path"),
}
_MODEL_LOAD_STRUCTURED_CONFIG_KEYS_BY_SUFFIX = {
    ".restore_from": frozenset({"override_config_path"}),
}
_MODEL_IDENTIFIER_ARGUMENTS = frozenset({"model_name", "model_name_or_path", "pretrained_model_name_or_path"})
_CONFIG_INTERPOLATION_RESOLVER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_.-]*):")
_NON_SYNTHESIZING_CONFIG_RESOLVERS = frozenset({"now", "oc.dict.keys", "oc.env"})
_NON_SYNTHESIZING_HYDRA_RESOLVER_RE = re.compile(
    r"\$\{hydra:(?:job\.(?:id|name|num|override_dirname)|runtime\.(?:cwd|output_dir)|sweep\.(?:dir|subdir))\}"
)
_MISSING_CONFIG_REFERENCE = object()
_SIMPLE_CONFIG_INTERPOLATION_RE = re.compile(r"\$\{([A-Za-z0-9_.-]+)\}")
_EXACT_SIMPLE_CONFIG_INTERPOLATION_RE = re.compile(r"^\$\{([A-Za-z0-9_.-]+)\}$")
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_HYDRA_DYNAMIC_CONFIG_SCAN_NODES = 1024

# Patterns in _target_ that are suspicious even if not exact matches
_SUSPICIOUS_TARGET_PATTERNS = (
    "eval",
    "exec",
    "system",
    "popen",
    "subprocess",
    "__import__",
    "pickle",
    "marshal",
    "compile",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
)
_TARGET_TOKEN_RE = re.compile(r"__import__|[A-Z]+(?=[A-Z][a-z0-9]|[0-9_]|$)|[A-Z]?[a-z0-9]+")
_HYDRA_INTERPOLATION_OPENER = "${"
_NEMO_MAX_CONFIG_EVIDENCE_CHARS = 256

CVE_2025_23304_ID = "CVE-2025-23304"
CVE_2025_23304_CVSS = 7.6
CVE_2025_23304_CWE = "CWE-94"
CVE_2025_23304_DESCRIPTION = (
    "NeMo Hydra _target_ specifies a suspicious or dangerous callable that may enable RCE when instantiated"
)
CVE_2025_23304_REMEDIATION = (
    "Update to NeMo >= 2.3.2 which validates _target_ values. Do not load untrusted .nemo files."
)
NEMO_CHECKPOINT_MEMBER_EXTENSIONS = frozenset({".ckpt", ".pt", ".pth", ".pkl", ".pickle"})
NEMO_MAX_CHECKPOINT_SCAN_BYTES = 50 * 1024 * 1024
NEMO_MAX_PYTHON_ANALYSIS_BYTES = 10 * 1024 * 1024
NEMO_MAX_LINK_RESOLUTION_MEMBER_VISITS = 100_000
NEMO_MAX_CONFIG_TRAVERSAL_DEPTH = 128
NEMO_MAX_CONFIG_TRAVERSAL_NODES = 100_000
NEMO_MAX_CONFIG_EVIDENCE_CHARS = 256
NEMO_EXECUTABLE_INITIAL_PROBE_BYTES = 1024
NEMO_EXECUTABLE_PE_PROBE_BYTES = (1024 * 1024) + 4

_INCONCLUSIVE_METADATA_KEY = "scan_outcome"
_INCONCLUSIVE_REASONS_METADATA_KEY = "scan_outcome_reasons"
_NESTED_OPERATIONAL_CHECK_NAMES = {
    "joblib_wrapper_decode_failed": "Compression Bomb Detection",
    "llamafile_routing_incomplete": "Llamafile Routing",
    "nemo_routing_incomplete": "NeMo Routing",
    "recognized_format_scanner_unavailable": "Format Detection",
    "xml_model_routing_incomplete": "XML Model Routing",
}
_NESTED_OPERATIONAL_REASON_FALLBACK = "nemo_referenced_nested_operational_error"
_NESTED_COVERAGE_ONLY_INCOMPLETE_REASONS = frozenset({"recognized_format_scanner_unavailable"})
_NESTED_COVERAGE_ONLY_INCOMPLETE_SUFFIXES = ("_routing_incomplete",)
_NESTED_NON_PROPAGATING_INCOMPLETE_REASONS = frozenset({"xgboost_binary_structure_too_small"})


class _NemoConfigTraversalLimit(Exception):
    """Raised when parsed YAML cannot be traversed within the safety budget."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _redact_config_evidence(value: str) -> str:
    """Bound attacker-controlled config evidence before storing diagnostics."""
    return redact_evidence_string(value, max_chars=NEMO_MAX_CONFIG_EVIDENCE_CHARS)


def _append_config_path(path_prefix: str, component: str) -> str:
    separator = "" if not path_prefix or component.startswith("[") else "."
    return _redact_config_evidence(f"{path_prefix}{separator}{component}")


def _find_suspicious_target_pattern(target: str) -> str | None:
    """Return a suspicious identifier token if a target contains one."""
    for component in target.split("."):
        for token in _TARGET_TOKEN_RE.findall(component):
            token_lower = token.lower()
            if token_lower in _SUSPICIOUS_TARGET_PATTERNS:
                return token_lower
            for pattern in _SUSPICIOUS_TARGET_PATTERNS:
                if token_lower.startswith(pattern) and token_lower[len(pattern) :].isdigit():
                    return pattern
    return None


def _find_suspicious_safe_prefixed_target_pattern(target: str) -> str | None:
    """Return a suspicious safe-prefixed callable leaf, if present."""
    leaf = target.rsplit(".", maxsplit=1)[-1].lower()
    if leaf in _SUSPICIOUS_TARGET_PATTERNS:
        return leaf
    for pattern in _SUSPICIOUS_TARGET_PATTERNS:
        if leaf.startswith(pattern) and leaf[len(pattern) :].isdigit():
            return pattern
    return None


def _unwrap_target_call_aliases(target: str) -> str:
    """Return the underlying callable for trailing ``.__call__`` aliases."""
    while target.endswith(_TARGET_CALL_ALIAS_SUFFIX):
        target = target[: -len(_TARGET_CALL_ALIAS_SUFFIX)]
    return target


def _is_dangerous_callable_target(callable_target: str) -> bool:
    """Return whether a Hydra callable target is an immediate dangerous sink."""
    return (
        callable_target in _DANGEROUS_TARGETS
        or callable_target.startswith(_DANGEROUS_TARGET_PREFIXES)
        or (callable_target.startswith("numpy.") and callable_target.endswith(_DANGEROUS_NUMPY_TARGET_SUFFIXES))
        or (
            callable_target not in _SAFE_TARGETS
            and callable_target.startswith("transformers.")
            and callable_target.endswith(_DANGEROUS_TRANSFORMERS_TARGET_SUFFIXES)
        )
    )


def _scan_result_has_security_findings(result: ScanResult) -> bool:
    return any(issue.severity in (IssueSeverity.WARNING, IssueSeverity.CRITICAL) for issue in result.issues)


def _is_nested_coverage_only_incomplete_reason(reason: str) -> bool:
    return reason in _NESTED_COVERAGE_ONLY_INCOMPLETE_REASONS or reason.endswith(
        _NESTED_COVERAGE_ONLY_INCOMPLETE_SUFFIXES
    )


def _is_nested_non_propagating_incomplete_reason(reason: str) -> bool:
    return reason in _NESTED_NON_PROPAGATING_INCOMPLETE_REASONS


def _append_incomplete_coverage_reason(reasons: list[str], candidate: Any) -> None:
    if isinstance(candidate, str) and candidate and candidate not in reasons:
        reasons.append(candidate)


def _incomplete_coverage_reasons_from_details(details: Any, *, _depth: int = 0) -> tuple[str, ...]:
    if not isinstance(details, dict) or _depth >= 4:
        return ()

    collected_reasons: list[str] = []
    _append_incomplete_coverage_reason(collected_reasons, details.get("scan_outcome_reason"))
    raw_reasons = details.get("scan_outcome_reasons")
    if isinstance(raw_reasons, str):
        _append_incomplete_coverage_reason(collected_reasons, raw_reasons)
    elif isinstance(raw_reasons, (list, tuple, set, frozenset)):
        for candidate in raw_reasons:
            _append_incomplete_coverage_reason(collected_reasons, candidate)

    findings = details.get("findings")
    if isinstance(findings, dict):
        for reason in _incomplete_coverage_reasons_from_details(findings, _depth=_depth + 1):
            _append_incomplete_coverage_reason(collected_reasons, reason)
    elif isinstance(findings, (list, tuple, set, frozenset)):
        for finding in findings:
            if isinstance(finding, dict):
                for reason in _incomplete_coverage_reasons_from_details(finding, _depth=_depth + 1):
                    _append_incomplete_coverage_reason(collected_reasons, reason)
                nested_details = finding.get("details")
                for reason in _incomplete_coverage_reasons_from_details(
                    nested_details,
                    _depth=_depth + 1,
                ):
                    _append_incomplete_coverage_reason(collected_reasons, reason)

    nested_details = details.get("details")
    if nested_details is not details:
        for reason in _incomplete_coverage_reasons_from_details(nested_details, _depth=_depth + 1):
            _append_incomplete_coverage_reason(collected_reasons, reason)

    return tuple(collected_reasons)


def _nested_record_incomplete_coverage_reasons(nested_result: ScanResult) -> tuple[str, ...]:
    reasons: list[str] = []
    for check in nested_result.checks:
        if not record_details_have_incomplete_coverage(check, allow_skipped_check_exemption=True):
            continue
        for reason in _incomplete_coverage_reasons_from_details(getattr(check, "details", None)):
            _append_incomplete_coverage_reason(reasons, reason)
    for issue in nested_result.issues:
        if not record_details_have_incomplete_coverage(issue):
            continue
        for reason in _incomplete_coverage_reasons_from_details(getattr(issue, "details", None)):
            _append_incomplete_coverage_reason(reasons, reason)
    return tuple(reasons)


def _select_nested_incomplete_propagation_reason(
    reasons: tuple[str, ...],
    *,
    nested_has_actionable_finding: bool,
) -> str | None:
    if nested_has_actionable_finding:
        return reasons[0] if reasons else _NESTED_OPERATIONAL_REASON_FALLBACK
    for reason in reasons:
        if _is_nested_coverage_only_incomplete_reason(reason):
            return reason
    for reason in reasons:
        if not _is_nested_non_propagating_incomplete_reason(reason):
            return reason
    return None


def _get_nested_scanner_for_file(path: str, *, config: dict[str, Any]) -> BaseScanner | None:
    """Resolve nested scanners lazily to avoid scanner registry import cycles."""
    from modelaudit.scanners import get_scanner_for_file

    return get_scanner_for_file(path, config=config)


class NemoScanner(BaseScanner):
    """Scanner for NVIDIA NeMo model files.

    Detects CVE-2025-23304: Hydra _target_ injection via malicious
    NeMo config metadata that enables remote code execution.
    """

    name = "nemo"
    description = "Scans NeMo files for Hydra _target_ injection (CVE-2025-23304)"
    supported_extensions: ClassVar[list[str]] = [".nemo"]

    # Maximum size for individual YAML configs to prevent YAML bombs
    MAX_CONFIG_SIZE: ClassVar[int] = 10 * 1024 * 1024  # 10MB

    @classmethod
    def can_handle(cls, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext in cls.supported_extensions:
            # Preserve legacy coverage for `.nemo` archives whose config is malformed or missing.
            return TarScanner.can_handle(path)
        return is_nemo_archive(path)

    @staticmethod
    def _archive_identity(stat_result: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_size,
            stat_result.st_mtime_ns,
            stat_result.st_ctime_ns,
        )

    @classmethod
    def _archive_source_changed(
        cls,
        path: str,
        archive_file: BinaryIO,
        expected_identity: tuple[int, int, int, int, int],
    ) -> bool:
        """Return whether the open archive or its pathname changed during analysis."""
        try:
            descriptor_identity = cls._archive_identity(os.fstat(archive_file.fileno()))
            path_identity = cls._archive_identity(os.stat(path))
        except OSError:
            return True
        return descriptor_identity != expected_identity or path_identity != expected_identity

    @staticmethod
    def _record_archive_identity_change(result: ScanResult, path: str) -> None:
        mark_archive_scan_incomplete(result, "nemo_archive_identity_changed")
        result.add_check(
            name="NeMo Archive Identity",
            passed=False,
            message="NeMo archive changed while it was being scanned",
            severity=IssueSeverity.INFO,
            location=path,
            details={
                "analysis_incomplete": True,
                "scan_outcome_reason": "nemo_archive_identity_changed",
            },
        )

    @staticmethod
    def _downgrade_identity_attributable_integrity_failure(result: ScanResult) -> None:
        for check in result.checks:
            if check.name == "NeMo Archive Integrity":
                check.severity = IssueSeverity.INFO
        for issue in result.issues:
            if issue.details.get("scan_outcome_reason") == "nemo_archive_integrity_incomplete":
                issue.severity = IssueSeverity.INFO

    def scan(self, path: str) -> ScanResult:
        budget_scanner = TarScanner(config=dict(self.config))
        with _tar_shared_scan_budget_scope(
            self.config,
            max_total_uncompressed_size=budget_scanner._get_max_total_uncompressed_size(),
        ):
            return self._scan_with_shared_tar_budget(path)

    def _scan_with_shared_tar_budget(self, path: str) -> ScanResult:
        path_check_result = self._check_path(path)
        if path_check_result:
            return path_check_result

        result = self._create_result()
        file_size = self.get_file_size(path)
        result.metadata["file_size"] = file_size
        is_declared_nemo = os.path.splitext(path)[1].lower() in self.supported_extensions

        tar_scanner = TarScanner(config=dict(self.config))
        try:
            archive_depth = max(int(self.config.get("_archive_depth", 0)), 0)
        except (TypeError, ValueError):
            archive_depth = 0
        if archive_depth >= tar_scanner.max_depth:
            result.merge(tar_scanner.scan(path))
            result.bytes_scanned = file_size
            self._finish_scan_result(result)
            return result

        preflight_result = ScanResult(scanner_name="tar")
        shared_budget = tar_scanner._get_or_create_shared_budget()
        initial_member_bytes = shared_budget.member_bytes_consumed
        initial_budget_exhausted = shared_budget.exhausted
        archive_file = open(path, "rb")  # noqa: SIM115 - descriptor spans preflight and analysis.
        try:
            initial_archive_identity = self._archive_identity(os.fstat(archive_file.fileno()))
            preflight_succeeded = tar_scanner._preflight_tar_archive(
                path,
                preflight_result,
                retain_member_budget=is_declared_nemo,
                raw_file=archive_file,
            )
        except BaseException:
            archive_file.close()
            raise
        if not preflight_succeeded:
            archive_source_changed = self._archive_source_changed(path, archive_file, initial_archive_identity)
            try:
                preflight_reasons = set(preflight_result.metadata.get("scan_outcome_reasons", []))
                mark_archive_scan_incomplete(preflight_result, "tar_analysis_incomplete")
                preflight_result.finish(success=False)
                result.merge(preflight_result)
                if preflight_reasons and preflight_reasons <= _PREFLIGHT_PREFIX_ANALYSIS_REASONS:
                    shared_budget.member_bytes_consumed = initial_member_bytes
                    shared_budget.exhausted = initial_budget_exhausted
                    result.merge(
                        tar_scanner._scan_tar_file(
                            path,
                            depth=archive_depth,
                            raw_file=archive_file,
                        )
                    )
            finally:
                archive_source_changed = archive_source_changed or self._archive_source_changed(
                    path,
                    archive_file,
                    initial_archive_identity,
                )
                archive_file.close()
            if archive_source_changed:
                for check in result.checks:
                    if check.details.get("scan_outcome_reason") in preflight_reasons:
                        check.severity = IssueSeverity.INFO
                for issue in result.issues:
                    if issue.details.get("scan_outcome_reason") in preflight_reasons:
                        issue.severity = IssueSeverity.INFO
                self._record_archive_identity_change(result, path)
            result.bytes_scanned = file_size
            self._finish_scan_result(result)
            return result

        if is_declared_nemo:
            preflight_result.finish(success=True)
            result.merge(preflight_result)

        nemo_owned_entries: set[str] = set()
        archive_source_changed = self._archive_source_changed(path, archive_file, initial_archive_identity)
        try:
            if not HAS_YAML:
                result.add_check(
                    name="YAML Parser Availability",
                    passed=False,
                    message="PyYAML not available; cannot analyze NeMo config for Hydra _target_ injection",
                    severity=IssueSeverity.WARNING,
                    location=path,
                )
            else:
                try:
                    self._scan_nemo_archive(
                        path,
                        result,
                        nemo_owned_entries,
                        archive_file=archive_file,
                        inspect_embedded_members=is_declared_nemo,
                    )
                except tarfile.TarError as e:
                    result.add_check(
                        name="NeMo Archive Integrity",
                        passed=False,
                        message=f"Failed to open NeMo archive: {e}",
                        severity=IssueSeverity.WARNING,
                        location=path,
                        details={
                            "analysis_incomplete": True,
                            "scan_outcome_reason": "nemo_archive_integrity_incomplete",
                        },
                    )
                    result.success = False
            if not is_declared_nemo:
                tar_config = dict(self.config)
                tar_config[TAR_SECURITY_ONLY_NESTED_MEMBER_ENTRIES_CONFIG_KEY] = nemo_owned_entries
                tar_config[TAR_SKIP_REACHABLE_NEMO_CONFIG_SCAN_KEY] = True
                # The enclosing NeMo result controls whether this artifact is
                # complete enough to cache; nested TAR dispatch must not persist partial results.
                tar_config["cache_enabled"] = False
                result.merge(
                    TarScanner(config=tar_config)._scan_tar_file(
                        path,
                        depth=archive_depth,
                        raw_file=archive_file,
                    )
                )
        finally:
            archive_source_changed = archive_source_changed or self._archive_source_changed(
                path,
                archive_file,
                initial_archive_identity,
            )
            archive_file.close()
        if archive_source_changed:
            self._downgrade_identity_attributable_integrity_failure(result)
            self._record_archive_identity_change(result, path)

        result.bytes_scanned = file_size
        self._finish_scan_result(result)
        return result

    def _mark_inconclusive_scan_result(
        self,
        result: ScanResult,
        *,
        reason: str,
        check_name: str,
        message: str,
        location: str,
        details: dict[str, Any] | None = None,
        severity: IssueSeverity = IssueSeverity.INFO,
    ) -> None:
        reasons = result.metadata.get(_INCONCLUSIVE_REASONS_METADATA_KEY)
        if not isinstance(reasons, list):
            reasons = []
        if reason not in reasons:
            reasons.append(reason)

        result.metadata[_INCONCLUSIVE_METADATA_KEY] = INCONCLUSIVE_SCAN_OUTCOME
        result.metadata[_INCONCLUSIVE_REASONS_METADATA_KEY] = reasons
        result.add_check(
            name=check_name,
            passed=False,
            message=message,
            severity=severity,
            location=location,
            details={"scan_outcome_reason": reason, **(details or {})},
        )

    @staticmethod
    def _finish_scan_result(result: ScanResult) -> None:
        if result.metadata.get("analysis_incomplete") is True:
            result.finish(success=False)
            return

        if result.metadata.get(
            _INCONCLUSIVE_METADATA_KEY
        ) == INCONCLUSIVE_SCAN_OUTCOME and not _scan_result_has_security_findings(result):
            result.finish(success=False)
            return

        result.finish(success=result.success and not result.has_errors)

    def _scan_nemo_archive(
        self,
        path: str,
        result: ScanResult,
        nemo_owned_entries: set[str],
        *,
        archive_file: BinaryIO,
        inspect_embedded_members: bool,
    ) -> None:
        """Extract and scan YAML configs from a NeMo tar archive."""
        yaml_configs_found = 0
        yaml_config_files_found = 0
        scanned_member_entries: set[str] = set()
        scanned_regular_checkpoint_sources: set[tuple[str, int]] = set()
        referenced_member_contexts: dict[str, tuple[str, str]] = {}
        scanned_yaml_sources: set[tuple[str, int]] = set()
        link_resolution_budget = [NEMO_MAX_LINK_RESOLUTION_MEMBER_VISITS]
        link_resolution_budget_reported = False
        linked_loaded_path_reported = False

        archive_file.seek(0)
        with tarfile.open(fileobj=archive_file, mode="r:*") as tar:
            archive_members = tar.getmembers()
            members_by_normalized_name: dict[str, list[tarfile.TarInfo]] = {}
            linked_loaded_paths: set[str] = set()
            loaded_path_link_present = self._archive_has_link_mediated_loaded_path(
                archive_members,
                link_resolution_budget,
            )
            for archive_member in archive_members:
                normalized_member_name = self._normalize_safe_archive_member_name(archive_member.name)
                if normalized_member_name is not None:
                    members_by_normalized_name.setdefault(normalized_member_name, []).append(archive_member)
                    if (
                        (archive_member.issym() or archive_member.islnk())
                        and self._resolve_archive_link_member_name(archive_member) is not None
                        and (
                            self._is_root_config_member_name(archive_member.name)
                            or archive_member.name.lower().endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS))
                        )
                    ):
                        linked_loaded_paths.add(normalized_member_name)

            def mark_linked_loaded_path_inconclusive() -> None:
                nonlocal linked_loaded_path_reported
                if linked_loaded_path_reported:
                    return
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_link_semantics_incomplete",
                    check_name="NeMo Link Semantics",
                    message=("NeMo loaded content is referenced through archive links; analysis is conservative"),
                    location=path,
                )
                linked_loaded_path_reported = True

            if loaded_path_link_present:
                mark_linked_loaded_path_inconclusive()
            if link_resolution_budget[0] < 0:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_link_resolution_budget_exceeded",
                    check_name="NeMo Link Resolution",
                    message="NeMo link analysis exceeded the member-visit safety limit",
                    location=path,
                )
                link_resolution_budget_reported = True

            for member in tar:
                self.check_interrupted()

                temp_base = os.path.join(tempfile.gettempdir(), "extract_nemo")
                resolved_member, member_path_safe = sanitize_archive_path(member.name, temp_base)
                if not member_path_safe:
                    self._add_archive_path_traversal_check(
                        result,
                        archive_path=path,
                        entry=member.name,
                        target=None,
                    )
                    continue

                name_lower = member.name.lower()
                if member.issym() or member.islnk():
                    target_base = os.path.dirname(resolved_member)
                    _target_resolved, target_safe = sanitize_archive_path(member.linkname, target_base)
                    if not target_safe:
                        self._add_archive_path_traversal_check(
                            result,
                            archive_path=path,
                            entry=member.name,
                            target=member.linkname,
                        )
                    elif name_lower.endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS)):
                        nemo_owned_entries.add(member.name)
                        if not self._is_final_archive_member_for_path(member, members_by_normalized_name):
                            continue
                        mark_linked_loaded_path_inconclusive()
                        link_target_name = self._resolve_archive_link_member_name(member)
                        if link_target_name is None:
                            self._mark_inconclusive_scan_result(
                                result,
                                reason="nemo_checkpoint_link_target_unresolved",
                                check_name="NeMo Checkpoint Nested Scan",
                                message=f"Could not resolve checkpoint link target: {member.name}",
                                location=f"{path}:{member.name}",
                                details={"entry": member.name, "target": member.linkname},
                            )
                        else:
                            target_members = members_by_normalized_name.get(link_target_name, [])
                            regular_target_member = self._resolve_extractable_regular_link_target(
                                member,
                                members_by_normalized_name,
                                archive_members,
                                link_resolution_budget,
                            )
                            if not target_members:
                                self._mark_inconclusive_scan_result(
                                    result,
                                    reason="nemo_checkpoint_link_target_missing",
                                    check_name="NeMo Checkpoint Nested Scan",
                                    message=f"Checkpoint link target not found: {member.name} -> {member.linkname}",
                                    location=f"{path}:{member.name}",
                                    details={"entry": member.name, "target": member.linkname},
                                )
                            elif member.islnk() and all(
                                target_member.offset >= member.offset for target_member in target_members
                            ):
                                self._mark_inconclusive_scan_result(
                                    result,
                                    reason="nemo_checkpoint_link_target_unresolved",
                                    check_name="NeMo Checkpoint Nested Scan",
                                    message=f"Checkpoint hardlink target appears after link entry: {member.name}",
                                    location=f"{path}:{member.name}",
                                    details={"entry": member.name, "target": member.linkname},
                                )
                            elif link_resolution_budget[0] < 0:
                                if not link_resolution_budget_reported:
                                    analysis_unsupported = link_resolution_budget[0] == -2
                                    self._mark_inconclusive_scan_result(
                                        result,
                                        reason=(
                                            "nemo_link_resolution_unsupported"
                                            if analysis_unsupported
                                            else "nemo_link_resolution_budget_exceeded"
                                        ),
                                        check_name="NeMo Link Resolution",
                                        message=(
                                            "NeMo link analysis could not safely model mixed link mutation"
                                            if analysis_unsupported
                                            else "NeMo link analysis exceeded the member-visit safety limit"
                                        ),
                                        location=path,
                                    )
                                    link_resolution_budget_reported = True
                            elif regular_target_member is not None:
                                self._scan_checkpoint_member(
                                    tar,
                                    regular_target_member,
                                    path,
                                    result,
                                    entry_name=member.name,
                                )
                            else:
                                self._mark_inconclusive_scan_result(
                                    result,
                                    reason="nemo_checkpoint_link_target_not_file",
                                    check_name="NeMo Checkpoint Nested Scan",
                                    message=f"Checkpoint link target is not a regular file: {member.name}",
                                    location=f"{path}:{member.name}",
                                    details={"entry": member.name, "target": member.linkname},
                                )
                    elif self._is_root_config_member_name(member.name):
                        if not self._is_final_archive_member_for_path(member, members_by_normalized_name):
                            continue
                        mark_linked_loaded_path_inconclusive()
                        link_target_name = self._resolve_archive_link_member_name(member)
                        if link_target_name is not None:
                            regular_target_member = self._resolve_extractable_regular_link_target(
                                member,
                                members_by_normalized_name,
                                archive_members,
                                link_resolution_budget,
                            )
                            if regular_target_member is not None:
                                target_member = regular_target_member
                                target_identity = self._tar_member_identity(target_member)
                                if target_identity in scanned_yaml_sources:
                                    continue
                                yaml_config_files_found += 1
                                if self._scan_yaml_config_member(
                                    tar,
                                    target_member,
                                    member.name,
                                    path,
                                    result,
                                    nemo_owned_entries,
                                    scanned_member_entries,
                                    scanned_regular_checkpoint_sources,
                                    referenced_member_contexts,
                                ):
                                    yaml_configs_found += 1
                                scanned_yaml_sources.add(target_identity)
                            elif link_resolution_budget[0] < 0 and not link_resolution_budget_reported:
                                analysis_unsupported = link_resolution_budget[0] == -2
                                self._mark_inconclusive_scan_result(
                                    result,
                                    reason=(
                                        "nemo_link_resolution_unsupported"
                                        if analysis_unsupported
                                        else "nemo_link_resolution_budget_exceeded"
                                    ),
                                    check_name="NeMo Link Resolution",
                                    message=(
                                        "NeMo link analysis could not safely model mixed link mutation"
                                        if analysis_unsupported
                                        else "NeMo link analysis exceeded the member-visit safety limit"
                                    ),
                                    location=path,
                                )
                                link_resolution_budget_reported = True
                    continue

                if not self._tar_member_materializes_file_content(member):
                    continue

                if inspect_embedded_members and not _tar_shared_scan_budget_exhausted(self.config):
                    self._scan_embedded_member_for_known_risks(tar, member, path, result)

                # Check for suspicious files in the archive
                if name_lower.endswith((".py", ".sh", ".bat", ".cmd", ".ps1")):
                    result.add_check(
                        name="Suspicious File in NeMo Archive",
                        passed=False,
                        message=(f"Executable file found in NeMo archive: {member.name}"),
                        severity=IssueSeverity.WARNING,
                        location=f"{path}:{member.name}",
                        details={"file": member.name},
                    )

                # Parse YAML config files
                if name_lower.endswith((".yaml", ".yml")):
                    normalized_member_name = self._normalize_safe_archive_member_name(member.name)
                    if normalized_member_name in linked_loaded_paths and self._is_root_config_member_name(member.name):
                        mark_linked_loaded_path_inconclusive()
                    member_identity = self._tar_member_identity(member)
                    if member_identity in scanned_yaml_sources:
                        continue
                    yaml_config_files_found += 1
                    if self._scan_yaml_config_member(
                        tar,
                        member,
                        member.name,
                        path,
                        result,
                        nemo_owned_entries,
                        scanned_member_entries,
                        scanned_regular_checkpoint_sources,
                        referenced_member_contexts,
                    ):
                        yaml_configs_found += 1
                    scanned_yaml_sources.add(member_identity)

                if name_lower.endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS)):
                    nemo_owned_entries.add(member.name)
                    normalized_member_name = self._normalize_safe_archive_member_name(member.name)
                    if normalized_member_name in linked_loaded_paths:
                        mark_linked_loaded_path_inconclusive()
                    member_identity = self._tar_member_identity(member)
                    if member.name in scanned_member_entries or member_identity in scanned_regular_checkpoint_sources:
                        continue
                    self._scan_checkpoint_member(tar, member, path, result)
                    scanned_regular_checkpoint_sources.add(member_identity)

        if referenced_member_contexts:
            referenced_link_mutation = self._archive_has_link_mediated_loaded_path(
                archive_members,
                link_resolution_budget,
                additional_loaded_member_names=set(referenced_member_contexts),
                include_default_loaded_member_names=False,
            )
            if referenced_link_mutation:
                referenced_entries = sorted(referenced_member_contexts)
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_referenced_link_semantics_incomplete",
                    check_name="NeMo Referenced Link Semantics",
                    message=("NeMo referenced content can be mutated through archive links; analysis is conservative"),
                    location=path,
                    details={
                        "entries": referenced_entries[:20],
                        "entry_count": len(referenced_entries),
                    },
                )
            elif link_resolution_budget[0] < 0:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_link_resolution_budget_exceeded",
                    check_name="NeMo Link Resolution",
                    message="NeMo link analysis exceeded the member-visit safety limit",
                    location=path,
                    details={"entry_count": len(referenced_member_contexts)},
                )

        if yaml_configs_found == 0:
            message = (
                "No YAML configuration found in NeMo archive"
                if yaml_config_files_found == 0
                else "No analyzable YAML configuration found in NeMo archive"
            )
            if yaml_config_files_found == 0:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_config_missing",
                    check_name="NeMo Config Presence",
                    message=message,
                    location=path,
                )
            else:
                result.add_check(
                    name="NeMo Config Presence",
                    passed=False,
                    message=message,
                    severity=IssueSeverity.INFO,
                    location=path,
                )
        else:
            result.add_check(
                name="NeMo Config Presence",
                passed=True,
                message=f"Found {yaml_configs_found} YAML config(s)",
                location=path,
            )

    def _scan_embedded_member_for_known_risks(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        """Apply bounded generic archive-member security checks inside NeMo files."""
        member_name_lower = member.name.lower()
        is_python_member = is_python_archive_member_name(member_name_lower)
        if is_executable_archive_member_name(member_name_lower):
            scan_archive_member_for_known_risks(
                archive_kind="NeMo",
                archive_path=archive_path,
                member_name=member.name,
                tmp_path=None,
                total_size=member.size,
                result=result,
                max_python_analysis_bytes=NEMO_MAX_PYTHON_ANALYSIS_BYTES,
                python_analysis_incomplete_reason="nemo_python_member_analysis_incomplete",
                executable_analysis_incomplete_reason="nemo_executable_member_analysis_incomplete",
            )
            return

        if is_python_member and member.size > NEMO_MAX_PYTHON_ANALYSIS_BYTES:
            scan_archive_member_for_known_risks(
                archive_kind="NeMo",
                archive_path=archive_path,
                member_name=member.name,
                tmp_path=None,
                total_size=member.size,
                result=result,
                max_python_analysis_bytes=NEMO_MAX_PYTHON_ANALYSIS_BYTES,
                python_analysis_incomplete_reason="nemo_python_member_analysis_incomplete",
                executable_analysis_incomplete_reason="nemo_executable_member_analysis_incomplete",
            )
            return

        max_bytes = None
        if not is_python_member:
            max_bytes = (
                NEMO_EXECUTABLE_PE_PROBE_BYTES
                if self._member_starts_with_portable_executable_magic(tar, member)
                else NEMO_EXECUTABLE_INITIAL_PROBE_BYTES
            )
        extracted_path = self._extract_member_to_tempfile(tar, member, max_bytes=max_bytes)
        if extracted_path is None:
            return

        try:
            scan_archive_member_for_known_risks(
                archive_kind="NeMo",
                archive_path=archive_path,
                member_name=member.name,
                tmp_path=extracted_path,
                total_size=member.size,
                result=result,
                max_python_analysis_bytes=NEMO_MAX_PYTHON_ANALYSIS_BYTES,
                python_analysis_incomplete_reason="nemo_python_member_analysis_incomplete",
                executable_analysis_incomplete_reason="nemo_executable_member_analysis_incomplete",
            )
        finally:
            try:
                os.unlink(extracted_path)
            except OSError:
                logger.debug("Failed to remove temporary NeMo member security file: %s", extracted_path)

    @staticmethod
    def _member_starts_with_portable_executable_magic(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bool:
        member_file = tar.extractfile(member)
        if member_file is None:
            return False
        with member_file:
            return member_file.read(2) == b"MZ"

    def _parse_yaml_config_bytes(
        self,
        raw: bytes,
        *,
        config_file: str,
        archive_path: str,
        result: ScanResult,
        declared_size: int | None = None,
    ) -> dict[Any, Any] | list[Any] | None:
        """Parse bounded NeMo YAML bytes with consistent incomplete outcomes."""
        config_size = declared_size if declared_size is not None else len(raw)
        if config_size > self.MAX_CONFIG_SIZE or len(raw) > self.MAX_CONFIG_SIZE:
            reported_size = max(config_size, len(raw))
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_config_size_limit",
                check_name="NeMo Config Size Check",
                message=f"Config file too large: {config_file} ({reported_size} bytes)",
                location=f"{archive_path}:{config_file}",
                severity=IssueSeverity.WARNING,
                details={
                    "config_file": config_file,
                    "size_bytes": reported_size,
                    "max_config_size": self.MAX_CONFIG_SIZE,
                },
            )
            return None

        if not HAS_YAML:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_yaml_parser_unavailable",
                check_name="YAML Parser Availability",
                message="PyYAML not available; cannot analyze NeMo config for Hydra _target_ injection",
                location=f"{archive_path}:{config_file}",
                severity=IssueSeverity.WARNING,
                details={"config_file": config_file},
            )
            return None

        try:
            parsed_config = yaml.safe_load(raw)
        except yaml.YAMLError:
            logger.debug("Failed to parse NeMo YAML config %s in %s", config_file, archive_path)
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_config_yaml_parse_failed",
                check_name="NeMo Config YAML Parsing",
                message=f"Failed to parse YAML config {config_file}",
                location=f"{archive_path}:{config_file}",
                details={"config_file": config_file},
            )
            return None
        except RecursionError:
            logger.debug("NeMo YAML config %s in %s exceeded parser recursion limits", config_file, archive_path)
            self._mark_config_traversal_inconclusive(
                result,
                config_file=config_file,
                archive_path=archive_path,
                reason="nemo_config_yaml_complexity_limit",
                message="YAML config exceeded parser complexity limits",
            )
            return None

        if not isinstance(parsed_config, dict | list):
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_config_invalid_structure",
                check_name="NeMo Config Structure",
                message=(f"YAML config {config_file} has unsupported top-level type: {type(parsed_config).__name__}"),
                location=f"{archive_path}:{config_file}",
                details={
                    "config_file": config_file,
                    "expected_type": "dict_or_list",
                    "actual_type": type(parsed_config).__name__,
                },
            )
            return None

        return parsed_config

    def scan_reachable_root_config_bytes(
        self,
        raw: bytes,
        *,
        config_file: str,
        archive_path: str,
        result: ScanResult,
        declared_size: int | None = None,
    ) -> bool:
        """Analyze root NeMo config bytes reached by a generic TAR scan."""
        config = self._parse_yaml_config_bytes(
            raw,
            config_file=config_file,
            archive_path=archive_path,
            result=result,
            declared_size=declared_size,
        )
        if config is None:
            return False

        try:
            self._check_hydra_targets(config, config_file, archive_path, result)
        except _NemoConfigTraversalLimit as exc:
            self._mark_config_traversal_inconclusive(
                result,
                config_file=config_file,
                archive_path=archive_path,
                reason=exc.reason,
                message=str(exc),
            )
            return False

        return True

    def _scan_yaml_config_member(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        config_file: str,
        archive_path: str,
        result: ScanResult,
        nemo_owned_entries: set[str],
        scanned_member_entries: set[str],
        scanned_regular_checkpoint_sources: set[tuple[str, int]],
        referenced_member_contexts: dict[str, tuple[str, str]],
    ) -> bool:
        """Analyze one YAML config entry, including a safe root-config link target."""
        if member.size > self.MAX_CONFIG_SIZE:
            self._parse_yaml_config_bytes(
                b"",
                config_file=config_file,
                archive_path=archive_path,
                result=result,
                declared_size=member.size,
            )
            return False

        member_file = tar.extractfile(member)
        if member_file is None:
            return False
        with member_file:
            raw = member_file.read(self.MAX_CONFIG_SIZE + 1)

        config = self._parse_yaml_config_bytes(
            raw,
            config_file=config_file,
            archive_path=archive_path,
            result=result,
            declared_size=member.size,
        )
        if config is None:
            return False

        try:
            self._check_hydra_targets(config, config_file, archive_path, result)
            referenced_members = self._collect_nemo_member_references(config)
        except _NemoConfigTraversalLimit as exc:
            self._mark_config_traversal_inconclusive(
                result,
                config_file=config_file,
                archive_path=archive_path,
                reason=exc.reason,
                message=str(exc),
            )
            return False

        nemo_owned_entries.update(referenced_member_name for _, referenced_member_name in referenced_members)
        for config_path, referenced_member_name in referenced_members:
            referenced_member_contexts.setdefault(referenced_member_name, (config_file, config_path))

        for config_path, referenced_member_name in referenced_members:
            if _tar_shared_scan_budget_exhausted(self.config):
                break
            if referenced_member_name in scanned_member_entries:
                continue
            referenced_member_scanned = self._scan_config_referenced_member(
                tar,
                referenced_member_name,
                archive_path,
                result,
                config_file=config_file,
                config_path=config_path,
                scanned_regular_checkpoint_sources=scanned_regular_checkpoint_sources,
            )
            if referenced_member_scanned:
                scanned_member_entries.add(referenced_member_name)
        return True

    def _mark_config_traversal_inconclusive(
        self,
        result: ScanResult,
        *,
        config_file: str,
        archive_path: str,
        reason: str,
        message: str,
    ) -> None:
        """Record bounded YAML traversal failures without retaining raw config evidence."""
        display_config_file = _redact_config_evidence(config_file)
        max_traversal_nodes = (
            _HYDRA_DYNAMIC_CONFIG_SCAN_NODES
            if reason == "nemo_helper_config_traversal_node_limit"
            else NEMO_MAX_CONFIG_TRAVERSAL_NODES
        )
        self._mark_inconclusive_scan_result(
            result,
            reason=reason,
            check_name="NeMo Config Traversal",
            message=f"{message}: {display_config_file}",
            location=f"{archive_path}:{display_config_file}",
            details={
                "config_file": display_config_file,
                "max_traversal_depth": NEMO_MAX_CONFIG_TRAVERSAL_DEPTH,
                "max_traversal_nodes": max_traversal_nodes,
            },
        )

    @staticmethod
    def _is_root_config_member_name(member_name: str) -> bool:
        normalized_name = NemoScanner._normalize_safe_archive_member_name(member_name)
        return normalized_name is not None and normalized_name.lower() in {"model_config.yaml", "model_config.yml"}

    @classmethod
    def _is_loaded_member_name(cls, member_name: str) -> bool:
        normalized_name = cls._normalize_safe_archive_member_name(member_name)
        return normalized_name is not None and (
            normalized_name.lower() in {"model_config.yaml", "model_config.yml"}
            or normalized_name.lower().endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS))
        )

    @classmethod
    def _archive_has_link_mediated_loaded_path(
        cls,
        archive_members: list[tarfile.TarInfo],
        member_visit_budget: list[int],
        *,
        additional_loaded_member_names: set[str] | None = None,
        include_default_loaded_member_names: bool = True,
    ) -> bool:
        """Return whether extracted link behavior can mutate loaded NeMo content."""
        additional_loaded_names = {
            normalized_name
            for member_name in additional_loaded_member_names or set()
            if (normalized_name := cls._normalize_safe_archive_member_name(member_name)) is not None
        }

        def is_loaded_member_name(member_name: str) -> bool:
            normalized_name = cls._normalize_safe_archive_member_name(member_name)
            return normalized_name is not None and (
                (include_default_loaded_member_names and cls._is_loaded_member_name(normalized_name))
                or normalized_name in additional_loaded_names
            )

        members_by_normalized_name: dict[str, list[tarfile.TarInfo]] = {}
        for archive_member in archive_members:
            normalized_name = cls._normalize_safe_archive_member_name(archive_member.name)
            if normalized_name is not None:
                members_by_normalized_name.setdefault(normalized_name, []).append(archive_member)

        symlink_targets: dict[str, str] = {}
        loaded_inode_paths: set[str] = set()
        occupied_names: set[str] = set()
        for member in archive_members:
            normalized_name = cls._normalize_safe_archive_member_name(member.name)
            if normalized_name is None:
                continue
            if member.issym():
                destination_name = cls._resolve_archive_path_through_symlinks(
                    normalized_name,
                    symlink_targets,
                    member_visit_budget,
                    follow_final_symlink=False,
                )
                if destination_name is None:
                    continue
                target_name = cls._resolve_archive_symlink_target_at_destination(member, destination_name)
                if target_name is None:
                    continue
                if is_loaded_member_name(destination_name):
                    return True
                loaded_inode_paths.discard(destination_name)
                occupied_names.add(destination_name)
                symlink_targets[destination_name] = target_name
                continue
            if member.islnk():
                destination_name = cls._resolve_archive_path_through_symlinks(
                    normalized_name,
                    symlink_targets,
                    member_visit_budget,
                    follow_final_symlink=False,
                )
                redirected_destination = cls._resolve_archive_path_through_symlinks(
                    normalized_name,
                    symlink_targets,
                    member_visit_budget,
                )
                target_name = cls._resolve_archive_link_member_name(member)
                if destination_name is None or target_name is None:
                    continue
                if is_loaded_member_name(destination_name):
                    return True
                if destination_name in occupied_names:
                    fallback_member = cls._resolve_hardlink_fallback_member(
                        member,
                        members_by_normalized_name,
                        member_visit_budget,
                    )
                    if fallback_member is None:
                        if redirected_destination is not None and (
                            is_loaded_member_name(redirected_destination)
                            or redirected_destination in loaded_inode_paths
                        ):
                            return True
                        continue
                    if fallback_member.issym():
                        loaded_inode_paths.discard(destination_name)
                        symlink_targets.pop(destination_name, None)
                        fallback_target = cls._resolve_archive_symlink_target_at_destination(
                            fallback_member,
                            destination_name,
                        )
                        if fallback_target is not None:
                            symlink_targets[destination_name] = fallback_target
                        continue
                    redirected_write = cls._resolve_archive_path_through_symlinks(
                        destination_name,
                        symlink_targets,
                        member_visit_budget,
                    )
                    if redirected_write is not None and (
                        is_loaded_member_name(redirected_write) or redirected_write in loaded_inode_paths
                    ):
                        return True
                    continue
                occupied_names.add(destination_name)
                redirected_target = cls._resolve_archive_path_through_symlinks(
                    target_name,
                    symlink_targets,
                    member_visit_budget,
                )
                if redirected_target is None:
                    continue
                fallback_member = cls._resolve_hardlink_fallback_member(
                    member,
                    members_by_normalized_name,
                    member_visit_budget,
                )
                if fallback_member is not None and fallback_member.issym() and redirected_target not in occupied_names:
                    fallback_target = cls._resolve_archive_symlink_target_at_destination(
                        fallback_member,
                        destination_name,
                    )
                    if fallback_target is not None:
                        symlink_targets[destination_name] = fallback_target
                    continue
                if redirected_target in loaded_inode_paths:
                    loaded_inode_paths.add(destination_name)
                continue
            if not cls._tar_member_materializes_file_content(member):
                continue
            destination_name = cls._resolve_archive_path_through_symlinks(
                normalized_name,
                symlink_targets,
                member_visit_budget,
            )
            if destination_name is None:
                continue
            physical_destination = cls._resolve_archive_path_through_symlinks(
                normalized_name,
                symlink_targets,
                member_visit_budget,
                follow_final_symlink=False,
            )
            if physical_destination is not None:
                occupied_names.add(physical_destination)
            if (destination_name != normalized_name and is_loaded_member_name(destination_name)) or (
                destination_name in loaded_inode_paths and not is_loaded_member_name(normalized_name)
            ):
                return True
            if is_loaded_member_name(destination_name):
                loaded_inode_paths.add(destination_name)
        return False

    @classmethod
    def _resolve_archive_path_through_symlinks(
        cls,
        member_name: str,
        symlink_targets: dict[str, str],
        member_visit_budget: list[int],
        *,
        follow_final_symlink: bool = True,
    ) -> str | None:
        """Resolve an extraction destination through symlinks already created."""
        current_name = cls._normalize_safe_archive_member_name(member_name)
        if current_name is None:
            return None
        seen: set[str] = set()
        while current_name not in seen:
            seen.add(current_name)
            if not symlink_targets:
                return current_name
            components = current_name.split("/")
            maximum_length = len(components) if follow_final_symlink else len(components) - 1
            if not cls._consume_archive_prefix_probe_budget(
                components,
                maximum_length,
                member_visit_budget,
            ):
                return None
            for length in range(maximum_length, 0, -1):
                prefix = "/".join(components[:length])
                target_name = symlink_targets.get(prefix)
                if target_name is None:
                    continue
                suffix = "/".join(components[length:])
                redirected_name = target_name if not suffix else posixpath.join(target_name, suffix)
                if posixpath.normpath(redirected_name) == ".":
                    current_name = "."
                else:
                    current_name = cls._normalize_safe_archive_member_name(redirected_name)
                    if current_name is None:
                        return None
                break
            else:
                return current_name
        return None

    @staticmethod
    def _consume_archive_prefix_probe_budget(
        components: list[str],
        maximum_length: int,
        member_visit_budget: list[int],
    ) -> bool:
        """Bound total prefix-string work before resolving symlink components."""
        prefix_length = 0
        probe_cost = 0
        for index, component in enumerate(components[:maximum_length]):
            prefix_length += len(component) + (1 if index else 0)
            probe_cost += prefix_length
            if probe_cost > member_visit_budget[0]:
                member_visit_budget[0] = -1
                return False
        member_visit_budget[0] -= probe_cost
        return True

    @classmethod
    def _resolve_archive_symlink_target_at_destination(
        cls,
        member: tarfile.TarInfo,
        destination_name: str,
    ) -> str | None:
        """Resolve a symlink target relative to its extracted destination."""
        linkname = member.linkname.replace("\\", "/")
        if is_absolute_archive_path(linkname):
            return None
        candidate = posixpath.join(posixpath.dirname(destination_name), linkname)
        if posixpath.normpath(candidate) == ".":
            return "."
        return cls._normalize_safe_archive_member_name(candidate)

    @staticmethod
    def _tar_member_identity(member: tarfile.TarInfo) -> tuple[str, int]:
        """Return an identity that distinguishes duplicate TAR entry headers."""
        return member.name, member.offset

    @classmethod
    def _is_final_archive_member_for_path(
        cls,
        member: tarfile.TarInfo,
        members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
    ) -> bool:
        """Return whether this header determines the extracted pathname."""
        normalized_name = cls._normalize_safe_archive_member_name(member.name)
        if normalized_name is None:
            return False
        path_members = members_by_normalized_name.get(normalized_name, [])
        return bool(path_members) and path_members[-1].offset == member.offset

    @staticmethod
    def _tar_member_materializes_file_content(member: tarfile.TarInfo) -> bool:
        """Mirror tarfile members extracted through makefile or makeunknown."""
        return not (
            member.isdir() or member.isfifo() or member.ischr() or member.isblk() or member.islnk() or member.issym()
        )

    @staticmethod
    def _normalize_safe_archive_member_name(member_name: str) -> str | None:
        """Normalize an archive member path that cannot escape extraction root."""
        normalized_name = posixpath.normpath(member_name.replace("\\", "/"))
        if is_absolute_archive_path(normalized_name):
            return None
        if normalized_name in {"", ".", ".."} or normalized_name.startswith("../"):
            return None
        return normalized_name

    @staticmethod
    def _resolve_archive_link_member_name(member: tarfile.TarInfo) -> str | None:
        """Resolve a tar link target to a normalized archive member name."""
        linkname = member.linkname.replace("\\", "/")
        if is_absolute_archive_path(linkname):
            return None

        if member.islnk():
            candidate = linkname
        else:
            member_dir = posixpath.dirname(member.name.replace("\\", "/"))
            candidate = posixpath.join(member_dir, linkname)
        if posixpath.normpath(candidate) == ".":
            return "."
        return NemoScanner._normalize_safe_archive_member_name(candidate)

    @classmethod
    def _resolve_extractable_regular_link_target(
        cls,
        root_link: tarfile.TarInfo,
        members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
        archive_members: list[tarfile.TarInfo],
        member_visit_budget: list[int],
    ) -> tarfile.TarInfo | None:
        """Resolve a safe TAR link chain to the regular entry extraction materializes."""
        pending = [root_link]
        seen: set[tuple[str, int]] = set()
        hardlink_members: list[tarfile.TarInfo] = []
        while pending:
            if member_visit_budget[0] <= 0:
                member_visit_budget[0] = -1
                return None
            member_visit_budget[0] -= 1
            member = pending.pop()
            identity = cls._tar_member_identity(member)
            if identity in seen:
                continue
            seen.add(identity)
            if cls._tar_member_materializes_file_content(member):
                if hardlink_members:
                    return cls._resolve_hardlink_inode_content(
                        root_link,
                        member,
                        members_by_normalized_name,
                        archive_members,
                        member_visit_budget,
                    )
                if root_link.issym():
                    return cls._resolve_symlink_only_content(
                        root_link,
                        archive_members,
                        member_visit_budget,
                    )
                return member
            if not (member.issym() or member.islnk()):
                continue
            if member.issym() and hardlink_members and root_link.islnk():
                member_visit_budget[0] = -2
                return None
            if member.islnk():
                hardlink_members.append(member)
            linked_member = cls._effective_archive_link_target_member(member, members_by_normalized_name)
            if linked_member is not None:
                pending.append(linked_member)
        return None

    @classmethod
    def _resolve_symlink_only_content(
        cls,
        observed_link: tarfile.TarInfo,
        archive_members: list[tarfile.TarInfo],
        member_visit_budget: list[int],
    ) -> tarfile.TarInfo | None:
        """Replay writes through an externally loaded symlink-only path."""
        if member_visit_budget[0] < len(archive_members):
            member_visit_budget[0] = -1
            return None
        member_visit_budget[0] -= len(archive_members)

        symlink_targets: dict[str, str] = {}
        content_by_name: dict[str, tarfile.TarInfo] = {}
        for archive_member in archive_members:
            member_name = cls._normalize_safe_archive_member_name(archive_member.name)
            if member_name is None:
                continue
            if archive_member.issym():
                destination_name = cls._resolve_archive_path_through_symlinks(
                    member_name,
                    symlink_targets,
                    member_visit_budget,
                    follow_final_symlink=False,
                )
                if destination_name is None:
                    return None
                target_name = cls._resolve_symlink_at_destination(archive_member, destination_name)
                if target_name is None:
                    return None
                symlink_targets[destination_name] = target_name
                content_by_name.pop(destination_name, None)
                continue
            if archive_member.islnk():
                member_visit_budget[0] = -2
                return None
            if cls._tar_member_materializes_file_content(archive_member):
                terminal_name = cls._resolve_symlink_terminal_name(
                    member_name,
                    symlink_targets,
                    member_visit_budget,
                )
                if terminal_name is None:
                    return None
                content_by_name[terminal_name] = archive_member

        observed_name = cls._normalize_safe_archive_member_name(observed_link.name)
        if observed_name is None:
            return None
        terminal_name = cls._resolve_symlink_terminal_name(observed_name, symlink_targets, member_visit_budget)
        if terminal_name is None:
            return None
        return content_by_name.get(terminal_name)

    @classmethod
    def _resolve_hardlink_inode_content(
        cls,
        observed_link: tarfile.TarInfo,
        initial_content: tarfile.TarInfo,
        members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
        archive_members: list[tarfile.TarInfo],
        member_visit_budget: list[int],
    ) -> tarfile.TarInfo | None:
        """Return final regular content of an extracted hardlink inode."""
        initial_name = cls._normalize_safe_archive_member_name(initial_content.name)
        observed_name = cls._normalize_safe_archive_member_name(observed_link.name)
        if initial_name is None or observed_name is None:
            return None
        if member_visit_budget[0] < len(archive_members):
            member_visit_budget[0] = -1
            return None
        member_visit_budget[0] -= len(archive_members)

        symlink_targets: dict[str, str] = {}
        ambiguous_fallback_symlink_destinations: set[str] = set()
        occupied_names: set[str] = set()
        for archive_member in archive_members:
            if archive_member.offset > initial_content.offset:
                break
            member_name = cls._normalize_safe_archive_member_name(archive_member.name)
            if member_name is None:
                continue
            destination_name = cls._resolve_archive_path_through_symlinks(
                member_name,
                symlink_targets,
                member_visit_budget,
                follow_final_symlink=False,
            )
            if destination_name is None:
                return None
            if archive_member.issym():
                symlink_target_name = cls._resolve_symlink_at_destination(
                    archive_member,
                    destination_name,
                )
                if symlink_target_name is None:
                    return None
                symlink_targets[destination_name] = symlink_target_name
                ambiguous_fallback_symlink_destinations.discard(destination_name)
            elif archive_member.islnk():
                fallback_member = cls._resolve_hardlink_fallback_member(
                    archive_member,
                    members_by_normalized_name,
                    member_visit_budget,
                )
                if fallback_member is None:
                    return None
                if fallback_member.issym():
                    symlink_targets.pop(destination_name, None)
                    symlink_target_name = cls._resolve_symlink_at_destination(
                        fallback_member,
                        destination_name,
                    )
                    if symlink_target_name is None:
                        return None
                    symlink_targets[destination_name] = symlink_target_name
                    if destination_name in occupied_names:
                        ambiguous_fallback_symlink_destinations.discard(destination_name)
                    else:
                        ambiguous_fallback_symlink_destinations.add(destination_name)
            occupied_names.add(destination_name)
        initial_destination_name = cls._resolve_archive_path_through_symlinks(
            initial_name,
            symlink_targets,
            member_visit_budget,
        )
        if initial_destination_name is None:
            return None
        if observed_link.islnk() and initial_destination_name != initial_name:
            member_visit_budget[0] = -2
            return None
        active_names = {initial_destination_name}
        effective_content = initial_content

        def traverses_ambiguous_fallback_symlink(member_name: str) -> bool:
            for ambiguous_destination in ambiguous_fallback_symlink_destinations:
                if cls._symlink_path_traverses_name(
                    member_name,
                    ambiguous_destination,
                    symlink_targets,
                    member_visit_budget,
                ):
                    return True
                if member_visit_budget[0] < 0:
                    return False
            return False

        for archive_member in archive_members:
            if archive_member.offset <= initial_content.offset:
                continue
            member_name = cls._normalize_safe_archive_member_name(archive_member.name)
            if member_name is None:
                continue
            destination_name = cls._resolve_archive_path_through_symlinks(
                member_name,
                symlink_targets,
                member_visit_budget,
                follow_final_symlink=False,
            )
            if destination_name is None:
                return None
            if cls._tar_member_materializes_file_content(archive_member):
                occupied_names.add(destination_name)
                resolves_to_inode = cls._path_resolves_to_hardlink_inode(
                    member_name,
                    active_names,
                    symlink_targets,
                    member_visit_budget,
                )
                if member_visit_budget[0] < 0:
                    return None
                if resolves_to_inode:
                    if traverses_ambiguous_fallback_symlink(member_name):
                        member_visit_budget[0] = -2
                        return None
                    if member_visit_budget[0] < 0:
                        return None
                    effective_content = archive_member
                continue

            if archive_member.islnk():
                destination_reaches_inode = cls._path_resolves_to_hardlink_inode(
                    member_name,
                    active_names,
                    symlink_targets,
                    member_visit_budget,
                )
                if member_visit_budget[0] < 0:
                    return None
                hardlink_target_name = cls._resolve_archive_link_member_name(archive_member)
                if destination_name in occupied_names:
                    destination_on_observed_path = cls._tar_member_identity(archive_member) == cls._tar_member_identity(
                        observed_link
                    ) or (
                        observed_link.issym()
                        and cls._symlink_path_traverses_name(
                            observed_name,
                            destination_name,
                            symlink_targets,
                            member_visit_budget,
                        )
                    )
                    if member_visit_budget[0] < 0:
                        return None
                    fallback_member = cls._resolve_hardlink_fallback_member(
                        archive_member,
                        members_by_normalized_name,
                        member_visit_budget,
                    )
                    if fallback_member is None:
                        return None
                    if fallback_member.issym():
                        active_names.discard(destination_name)
                        symlink_targets.pop(destination_name, None)
                        symlink_target_name = cls._resolve_symlink_at_destination(
                            fallback_member,
                            destination_name,
                        )
                        if symlink_target_name is None:
                            return None
                        symlink_targets[destination_name] = symlink_target_name
                        ambiguous_fallback_symlink_destinations.discard(destination_name)
                        continue
                    if destination_reaches_inode or destination_on_observed_path:
                        if cls._tar_member_materializes_file_content(fallback_member):
                            effective_content = fallback_member
                            if destination_on_observed_path and not destination_reaches_inode:
                                symlink_targets.pop(destination_name, None)
                                active_names.add(destination_name)
                        else:
                            return None
                    continue
                occupied_names.add(destination_name)
                if hardlink_target_name is not None:
                    target_reaches_inode = cls._path_resolves_to_hardlink_inode(
                        hardlink_target_name,
                        active_names,
                        symlink_targets,
                        member_visit_budget,
                    )
                    if member_visit_budget[0] < 0:
                        return None
                    if target_reaches_inode:
                        if traverses_ambiguous_fallback_symlink(hardlink_target_name):
                            member_visit_budget[0] = -2
                            return None
                        if member_visit_budget[0] < 0:
                            return None
                        active_names.add(destination_name)
                    else:
                        fallback_member = cls._resolve_hardlink_fallback_member(
                            archive_member,
                            members_by_normalized_name,
                            member_visit_budget,
                        )
                        if fallback_member is not None and fallback_member.issym():
                            symlink_target_name = cls._resolve_symlink_at_destination(
                                fallback_member,
                                destination_name,
                            )
                            if symlink_target_name is None:
                                return None
                            symlink_targets[destination_name] = symlink_target_name
                            ambiguous_fallback_symlink_destinations.add(destination_name)
            elif archive_member.issym():
                active_names.discard(destination_name)
                symlink_targets.pop(destination_name, None)
                occupied_names.add(destination_name)
                symlink_target_name = cls._resolve_symlink_at_destination(
                    archive_member,
                    destination_name,
                )
                if symlink_target_name is not None:
                    symlink_targets[destination_name] = symlink_target_name
                    ambiguous_fallback_symlink_destinations.discard(destination_name)

        observed_reaches_inode = cls._path_resolves_to_hardlink_inode(
            observed_name,
            active_names,
            symlink_targets,
            member_visit_budget,
        )
        if member_visit_budget[0] < 0:
            return None
        return effective_content if observed_reaches_inode else None

    @classmethod
    def _symlink_path_traverses_name(
        cls,
        start_name: str,
        candidate_name: str,
        symlink_targets: dict[str, str],
        member_visit_budget: list[int],
    ) -> bool:
        """Return whether a symlink path currently traverses a candidate name."""
        normalized_candidate = cls._normalize_safe_archive_member_name(candidate_name)
        current_name = cls._normalize_safe_archive_member_name(start_name)
        if normalized_candidate is None or current_name is None:
            return False
        seen: set[str] = set()
        while current_name not in seen:
            if current_name == normalized_candidate:
                return True
            seen.add(current_name)
            if not symlink_targets:
                return False
            components = current_name.split("/")
            if not cls._consume_archive_prefix_probe_budget(
                components,
                len(components),
                member_visit_budget,
            ):
                return False
            for length in range(len(components), 0, -1):
                prefix = "/".join(components[:length])
                target_name = symlink_targets.get(prefix)
                if target_name is None:
                    continue
                if prefix == normalized_candidate:
                    return True
                suffix = "/".join(components[length:])
                redirected_name = target_name if not suffix else posixpath.join(target_name, suffix)
                if posixpath.normpath(redirected_name) == ".":
                    current_name = "."
                    break
                normalized_redirected = cls._normalize_safe_archive_member_name(redirected_name)
                if normalized_redirected is None:
                    return False
                current_name = normalized_redirected
                break
            else:
                return False
        return False

    @classmethod
    def _resolve_hardlink_fallback_member(
        cls,
        hardlink: tarfile.TarInfo,
        members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
        member_visit_budget: list[int],
    ) -> tarfile.TarInfo | None:
        """Resolve the member extracted by a colliding hardlink fallback."""
        pending = hardlink
        seen: set[tuple[str, int]] = set()
        while pending.islnk():
            if member_visit_budget[0] <= 0:
                member_visit_budget[0] = -1
                return None
            member_visit_budget[0] -= 1
            identity = cls._tar_member_identity(pending)
            if identity in seen:
                return None
            seen.add(identity)
            target_member = cls._effective_archive_link_target_member(pending, members_by_normalized_name)
            if target_member is None:
                return None
            if cls._tar_member_materializes_file_content(target_member) or target_member.issym():
                return target_member
            pending = target_member
        return None

    @classmethod
    def _resolve_symlink_at_destination(cls, symlink: tarfile.TarInfo, destination_name: str) -> str | None:
        """Resolve a fallback symlink relative to the path where TAR installs it."""
        linkname = symlink.linkname.replace("\\", "/")
        if is_absolute_archive_path(linkname):
            return None
        candidate = posixpath.join(posixpath.dirname(destination_name), linkname)
        if posixpath.normpath(candidate) == ".":
            return "."
        return cls._normalize_safe_archive_member_name(candidate)

    @classmethod
    def _path_resolves_to_hardlink_inode(
        cls,
        member_name: str,
        active_names: set[str],
        symlink_targets: dict[str, str],
        member_visit_budget: list[int],
    ) -> bool:
        """Return whether opening a safe path reaches the tracked hardlink inode."""
        terminal_name = cls._resolve_archive_path_through_symlinks(
            member_name,
            symlink_targets,
            member_visit_budget,
        )
        return terminal_name is not None and terminal_name in active_names

    @classmethod
    def _resolve_symlink_terminal_name(
        cls,
        member_name: str,
        symlink_targets: dict[str, str],
        member_visit_budget: list[int],
    ) -> str | None:
        """Resolve a safe extracted symlink chain to its terminal pathname."""
        return cls._resolve_archive_path_through_symlinks(
            member_name,
            symlink_targets,
            member_visit_budget,
        )

    @classmethod
    def _effective_archive_link_target_member(
        cls,
        member: tarfile.TarInfo,
        members_by_normalized_name: dict[str, list[tarfile.TarInfo]],
    ) -> tarfile.TarInfo | None:
        """Return the single target entry TAR extraction would use for a link."""
        target_name = cls._resolve_archive_link_member_name(member)
        if target_name is None:
            return None
        target_members = members_by_normalized_name.get(target_name, [])
        if member.islnk():
            target_members = [target_member for target_member in target_members if target_member.offset < member.offset]
        return target_members[-1] if target_members else None

    def _add_archive_path_traversal_check(
        self,
        result: ScanResult,
        *,
        archive_path: str,
        entry: str,
        target: str | None,
    ) -> None:
        """Report NeMo archive member paths that can escape extraction roots."""
        path_value = target or entry
        if is_absolute_archive_path(path_value):
            cve_id = "CVE-2025-23250"
            cvss = 7.6
            cwe = "CWE-22"
            description = (
                "NVIDIA NeMo Framework archive loading can improperly limit absolute or out-of-root paths, "
                "allowing arbitrary file writes from crafted model archives."
            )
            remediation = "Update NVIDIA NeMo Framework to release 25.02 or later and reject unsafe archive paths."
        else:
            cve_id = "CVE-2025-23360"
            cvss = 7.1
            cwe = "CWE-23"
            description = (
                "NVIDIA NeMo Framework archive loading can process relative path traversal entries, allowing "
                "crafted model archives to write files outside the intended extraction directory."
            )
            remediation = "Update NVIDIA NeMo Framework to release 24.12 or later and reject relative traversal paths."

        result.add_check(
            name=f"{cve_id}: NeMo Archive Path Traversal",
            passed=False,
            message=(
                f"{cve_id}: NeMo archive member '{entry}'"
                + (f" links to unsafe target '{target}'" if target is not None else " escapes extraction root")
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{entry}",
            details={
                "entry": entry,
                "target": target,
                "cve_id": cve_id,
                "cvss": cvss,
                "cwe": cwe,
                "description": description,
                "remediation": remediation,
            },
            why=(
                "The .nemo file is a tar archive. This member path would escape the intended extraction "
                "directory in vulnerable NeMo loaders, creating an arbitrary file-write risk."
            ),
        )

    def _scan_checkpoint_member(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        archive_path: str,
        result: ScanResult,
        *,
        entry_name: str | None = None,
    ) -> None:
        """Run existing nested scanners over small NeMo checkpoint members."""
        if _tar_shared_scan_budget_exhausted(self.config):
            return

        report_entry = entry_name or member.name
        max_scan_bytes = self._normalize_positive_int_config(
            self.config.get("max_nemo_checkpoint_scan_bytes"),
            NEMO_MAX_CHECKPOINT_SCAN_BYTES,
        )
        if member.size > max_scan_bytes:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_scan_skipped_size_limit",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Checkpoint member exceeds nested scan limit: {report_entry}",
                location=f"{archive_path}:{report_entry}",
                details={
                    "entry": report_entry,
                    "source_entry": member.name,
                    "size_bytes": member.size,
                    "max_scan_bytes": max_scan_bytes,
                },
            )
            return

        extracted_path = self._extract_member_to_tempfile(tar, member, suffix_source=report_entry)
        if extracted_path is None:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_extract_failed",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Could not extract checkpoint member for nested scan: {report_entry}",
                location=f"{archive_path}:{report_entry}",
                details={"entry": report_entry, "source_entry": member.name},
            )
            return

        try:
            scanner = _get_nested_scanner_for_file(extracted_path, config=dict(self.config))
            if scanner is None:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_checkpoint_no_nested_scanner",
                    check_name="NeMo Checkpoint Nested Scan",
                    message=f"No nested scanner available for checkpoint member: {report_entry}",
                    location=f"{archive_path}:{report_entry}",
                    details={"entry": report_entry, "source_entry": member.name},
                )
                return

            try:
                nested_result = scanner.scan(extracted_path)
            except Exception as exc:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_checkpoint_nested_scan_failed",
                    check_name="NeMo Checkpoint Nested Scan",
                    message=f"Nested scan failed for checkpoint member {report_entry}: {exc!s}",
                    location=f"{archive_path}:{report_entry}",
                    details={
                        "entry": report_entry,
                        "source_entry": member.name,
                        "nested_scanner": scanner.name,
                        "exception_type": type(exc).__name__,
                    },
                )
                return

            self._merge_nested_security_findings(result, nested_result, extracted_path, archive_path, report_entry)
            critical_issues = [
                issue
                for issue in nested_result.issues
                if issue.severity == IssueSeverity.CRITICAL
                and self._is_nested_checkpoint_deserialization_issue(issue, nested_result.scanner_name)
            ]
            if critical_issues:
                self._add_checkpoint_deserialization_check(
                    result,
                    archive_path=archive_path,
                    entry=report_entry,
                    nested_scanner=nested_result.scanner_name,
                    critical_issues=critical_issues,
                )
        finally:
            try:
                os.unlink(extracted_path)
            except OSError:
                logger.debug("Failed to remove temporary NeMo checkpoint scan file: %s", extracted_path)

    def _scan_config_referenced_member(
        self,
        tar: tarfile.TarFile,
        referenced_member_name: str,
        archive_path: str,
        result: ScanResult,
        *,
        config_file: str,
        config_path: str,
        scanned_regular_checkpoint_sources: set[tuple[str, int]],
    ) -> bool:
        """Scan `nemo:`-referenced archive members through content-based nested dispatch."""
        if _tar_shared_scan_budget_exhausted(self.config):
            return False

        try:
            member = tar.getmember(referenced_member_name)
        except KeyError:
            return False

        if (
            member.isfile()
            and referenced_member_name.lower().endswith(tuple(NEMO_CHECKPOINT_MEMBER_EXTENSIONS))
            and self._tar_member_identity(member) in scanned_regular_checkpoint_sources
        ):
            return True

        if member.issym() or member.islnk():
            resolved_name = self._resolve_archive_link_member_name(member)
            if resolved_name is None:
                return False
            try:
                member = tar.getmember(resolved_name)
            except KeyError:
                return False

        if not member.isfile():
            return False

        max_scan_bytes = self._normalize_positive_int_config(
            self.config.get("max_nemo_checkpoint_scan_bytes"),
            NEMO_MAX_CHECKPOINT_SCAN_BYTES,
        )
        if member.size > max_scan_bytes:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_scan_skipped_size_limit",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Referenced member exceeds nested scan limit: {referenced_member_name}",
                location=f"{archive_path}:{referenced_member_name}",
                details={
                    "entry": referenced_member_name,
                    "source_entry": member.name,
                    "config_file": config_file,
                    "config_path": config_path,
                    "size_bytes": member.size,
                    "max_scan_bytes": max_scan_bytes,
                },
            )
            return True

        extracted_path = self._extract_member_to_tempfile(tar, member, suffix_source=referenced_member_name)
        if extracted_path is None:
            self._mark_inconclusive_scan_result(
                result,
                reason="nemo_checkpoint_extract_failed",
                check_name="NeMo Checkpoint Nested Scan",
                message=f"Could not extract referenced member for nested scan: {referenced_member_name}",
                location=f"{archive_path}:{referenced_member_name}",
                details={
                    "entry": referenced_member_name,
                    "source_entry": member.name,
                    "config_file": config_file,
                    "config_path": config_path,
                },
            )
            return True

        try:
            from .archive_dispatch import scan_nested_file

            try:
                nested_result = scan_nested_file(extracted_path, config=dict(self.config))
            except Exception as exc:
                self._mark_inconclusive_scan_result(
                    result,
                    reason="nemo_referenced_nested_scan_failed",
                    check_name="NeMo Checkpoint Nested Scan",
                    message=f"Nested scan failed for referenced member {referenced_member_name}: {exc!s}",
                    location=f"{archive_path}:{referenced_member_name}",
                    details={
                        "entry": referenced_member_name,
                        "source_entry": member.name,
                        "config_file": config_file,
                        "config_path": config_path,
                        "exception_type": type(exc).__name__,
                        "exception_message": str(exc),
                    },
                )
                return True

            self._merge_nested_security_findings(
                result,
                nested_result,
                extracted_path,
                archive_path,
                referenced_member_name,
            )
            critical_issues = [
                issue
                for issue in nested_result.issues
                if issue.severity == IssueSeverity.CRITICAL
                and self._is_nested_checkpoint_deserialization_issue(issue, nested_result.scanner_name)
            ]
            if critical_issues:
                self._add_checkpoint_deserialization_check(
                    result,
                    archive_path=archive_path,
                    entry=referenced_member_name,
                    nested_scanner=nested_result.scanner_name,
                    critical_issues=critical_issues,
                    extra_details={
                        "config_file": config_file,
                        "config_path": config_path,
                        "source_entry": member.name,
                    },
                )
            return True
        finally:
            try:
                os.unlink(extracted_path)
            except OSError:
                logger.debug("Failed to remove temporary NeMo referenced scan file: %s", extracted_path)

    @staticmethod
    def _merge_nested_security_findings(
        result: ScanResult,
        nested_result: ScanResult,
        extracted_path: str,
        archive_path: str,
        entry_name: str,
    ) -> None:
        """Preserve actionable nested findings while NeMo adds CVE attribution."""
        archive_location = f"{archive_path}:{entry_name}"
        actionable_severities = {IssueSeverity.WARNING, IssueSeverity.CRITICAL}
        raw_operational_reason = nested_result.metadata.get(OPERATIONAL_ERROR_REASON_METADATA_KEY)
        raw_incomplete_reason = nested_result.metadata.get("scan_outcome_reason")
        raw_incomplete_reasons = nested_result.metadata.get("scan_outcome_reasons")
        reason_candidates: list[str] = []
        _append_incomplete_coverage_reason(reason_candidates, raw_operational_reason)
        _append_incomplete_coverage_reason(reason_candidates, raw_incomplete_reason)
        if isinstance(raw_incomplete_reasons, str):
            _append_incomplete_coverage_reason(reason_candidates, raw_incomplete_reasons)
        elif isinstance(raw_incomplete_reasons, (list, tuple, set, frozenset)):
            for reason in raw_incomplete_reasons:
                _append_incomplete_coverage_reason(reason_candidates, reason)
        for reason in _nested_record_incomplete_coverage_reasons(nested_result):
            _append_incomplete_coverage_reason(reason_candidates, reason)
        operational_reason = reason_candidates[0] if reason_candidates else _NESTED_OPERATIONAL_REASON_FALLBACK
        nested_incomplete = (
            metadata_has_incomplete_coverage(nested_result.metadata)
            or records_have_incomplete_coverage(nested_result.checks, allow_skipped_check_exemption=True)
            or records_have_incomplete_coverage(nested_result.issues)
        )
        nested_operational = scan_result_has_operational_error(nested_result)
        nested_has_actionable_finding = any(
            check.status == CheckStatus.FAILED and check.severity in actionable_severities
            for check in nested_result.checks
        ) or any(issue.severity in actionable_severities for issue in nested_result.issues)
        propagation_reason = _select_nested_incomplete_propagation_reason(
            tuple(reason_candidates) if reason_candidates else (_NESTED_OPERATIONAL_REASON_FALLBACK,),
            nested_has_actionable_finding=nested_has_actionable_finding,
        )
        nested_incomplete_should_propagate = nested_incomplete and propagation_reason is not None
        if nested_operational or nested_incomplete_should_propagate:
            archive_incomplete_reason = operational_reason if nested_operational else propagation_reason
            if archive_incomplete_reason is not None:
                mark_archive_scan_incomplete(result, archive_incomplete_reason)
        if nested_operational:
            mark_operational_scan_error(result, operational_reason)

        for check in nested_result.checks:
            is_operational_diagnostic = nested_operational and (
                check.name == _NESTED_OPERATIONAL_CHECK_NAMES.get(operational_reason)
                or check.details.get("scan_outcome_reason") == operational_reason
            )
            if check.status != CheckStatus.FAILED or (
                check.severity not in actionable_severities and not is_operational_diagnostic
            ):
                continue
            check.location = rewrite_extracted_member_location(
                check.location,
                extracted_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )
            result.checks.append(check)
        for issue in nested_result.issues:
            if issue.severity not in actionable_severities:
                continue
            issue.location = rewrite_extracted_member_location(
                issue.location,
                extracted_path,
                archive_location,
                preserve_non_delimited_suffix=False,
            )
            result.issues.append(issue)

    @classmethod
    def _collect_nemo_member_references(
        cls,
        config: Any,
        path_prefix: str = "",
    ) -> list[tuple[str, str]]:
        """Collect internal `nemo:` artifact references from a parsed config."""
        collected: list[tuple[str, str]] = []
        for config_path, value, _parent, _key in cls._iter_config_nodes(config, path_prefix=path_prefix):
            if not isinstance(value, str):
                continue
            member_name = cls._extract_nemo_member_reference(value)
            if member_name is not None:
                collected.append((config_path or "$", member_name))

        return collected

    @classmethod
    def _iter_config_nodes(
        cls,
        config: Any,
        *,
        path_prefix: str = "",
    ) -> Iterator[tuple[str, Any, dict[Any, Any] | None, Any]]:
        """Yield parsed config nodes while bounding depth, work, and YAML alias cycles."""
        visited_nodes = 0
        expanded_containers: set[int] = set()

        def walk(
            value: Any,
            config_path: str,
            depth: int,
            ancestors: frozenset[int],
            parent: dict[Any, Any] | None,
            key: Any,
        ) -> Iterator[tuple[str, Any, dict[Any, Any] | None, Any]]:
            nonlocal visited_nodes
            visited_nodes += 1
            if visited_nodes > NEMO_MAX_CONFIG_TRAVERSAL_NODES:
                raise _NemoConfigTraversalLimit(
                    "nemo_config_traversal_node_limit",
                    "YAML config exceeded the traversal node safety limit",
                )

            if isinstance(value, dict | list):
                identity = id(value)
                if identity in ancestors:
                    raise _NemoConfigTraversalLimit(
                        "nemo_config_recursive_alias",
                        "YAML config contains a recursive alias",
                    )
                if depth > NEMO_MAX_CONFIG_TRAVERSAL_DEPTH:
                    raise _NemoConfigTraversalLimit(
                        "nemo_config_traversal_depth_limit",
                        "YAML config exceeded the traversal depth safety limit",
                    )

            yield config_path, value, parent, key

            if isinstance(value, dict | list):
                # YAML aliases reuse container identities; expand each once to bound
                # repeated work and duplicate diagnostics while retaining cycle checks.
                if identity in expanded_containers:
                    return
                expanded_containers.add(identity)
                child_ancestors = ancestors | {identity}
                if isinstance(value, dict):
                    if "_target_" in value:
                        child_path = _append_config_path(config_path, "_target_")
                        yield from walk(
                            value["_target_"],
                            child_path,
                            depth + 1,
                            child_ancestors,
                            value,
                            "_target_",
                        )
                    for child_key, child_value in value.items():
                        if child_key == "_target_":
                            continue
                        child_path = _append_config_path(config_path, str(child_key))
                        yield from walk(child_value, child_path, depth + 1, child_ancestors, value, child_key)
                else:
                    for index, child_value in enumerate(value):
                        child_path = _append_config_path(config_path, f"[{index}]")
                        yield from walk(child_value, child_path, depth + 1, child_ancestors, None, index)

        yield from walk(config, path_prefix, 0, frozenset(), None, None)

    @staticmethod
    def _extract_nemo_member_reference(value: str) -> str | None:
        normalized = value.strip()
        if not normalized or ":" not in normalized:
            return None

        scheme, member_name = normalized.split(":", 1)
        if scheme.lower() != "nemo":
            return None

        member_name = member_name.strip().replace("\\", "/")
        if not member_name:
            return None

        normalized_member = os.path.normpath(member_name).replace("\\", "/")
        if (
            normalized_member in {"", ".", ".."}
            or normalized_member.startswith("../")
            or is_absolute_archive_path(normalized_member)
        ):
            return None

        return normalized_member.lstrip("./")

    @staticmethod
    def _is_nested_checkpoint_deserialization_issue(issue: Any, nested_scanner: str | None = None) -> bool:
        details = issue.details if isinstance(issue.details, dict) else {}
        if nested_scanner == "torch7" and details.get("signal") == "exec_with_network_shell_context":
            return True

        text = " ".join(
            str(part).lower()
            for part in (
                issue.message,
                issue.type,
                issue.rule_code,
                details.get("cve_id", ""),
                details.get("opcode", ""),
                details.get("symbol", ""),
                details.get("function", ""),
            )
        )
        return any(
            indicator in text
            for indicator in (
                "pickle",
                "unpickle",
                "deserial",
                "opcode",
                "global",
                "reduce",
                "torch.load",
                "arbitrary code",
                "cve-2020-13092",
                "cve-2025-1716",
                "cve-2025-32434",
            )
        )

    @staticmethod
    def _extract_member_to_tempfile(
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        *,
        suffix_source: str | None = None,
        max_bytes: int | None = None,
    ) -> str | None:
        member_file = tar.extractfile(member)
        if member_file is None:
            return None

        _root, suffix = os.path.splitext(suffix_source or member.name)
        with member_file, tempfile.NamedTemporaryFile(suffix=suffix or ".bin", delete=False) as temp_file:
            remaining = max_bytes
            while True:
                if remaining is not None and remaining <= 0:
                    break
                chunk = member_file.read(64 * 1024 if remaining is None else min(64 * 1024, remaining))
                if not chunk:
                    break
                temp_file.write(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
            return temp_file.name

    def _add_checkpoint_deserialization_check(
        self,
        result: ScanResult,
        *,
        archive_path: str,
        entry: str,
        nested_scanner: str,
        critical_issues: list[Any],
        extra_details: dict[str, Any] | None = None,
    ) -> None:
        result.add_check(
            name="CVE-2025-23249: NeMo Checkpoint Unsafe Deserialization",
            passed=False,
            message=(
                "CVE-2025-23249: NeMo checkpoint member contains unsafe deserialization payloads "
                f"detected by {nested_scanner}"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{entry}",
            details={
                "entry": entry,
                "nested_scanner": nested_scanner,
                "critical_issue_count": len(critical_issues),
                "sample_issue_messages": [issue.message for issue in critical_issues[:3]],
                "cve_id": "CVE-2025-23249",
                "cvss": 7.6,
                "cwe": "CWE-502",
                "description": (
                    "NVIDIA NeMo Framework contains unsafe deserialization paths for untrusted model data. "
                    "A crafted checkpoint inside a .nemo archive can trigger code execution when loaded."
                ),
                "related_cves": ["CVE-2025-33253", "CVE-2026-24157"],
                "remediation": (
                    "Update NVIDIA NeMo Framework to release 25.02 or later, keep current with subsequent "
                    "checkpoint-loading fixes, and reject untrusted checkpoint payloads."
                ),
                **(extra_details or {}),
            },
            why=(
                "A nested scanner found critical unsafe-deserialization behavior inside a checkpoint bundled "
                "in the .nemo archive. Vulnerable NeMo loaders may deserialize these checkpoints during model load."
            ),
        )

    def _check_hydra_targets(
        self,
        config: Any,
        config_name: str,
        archive_path: str,
        result: ScanResult,
        path_prefix: str = "",
    ) -> None:
        """Check _target_ values in Hydra config within shared traversal bounds."""
        helper_scan_state: dict[str, Any] = {
            "remaining": _HYDRA_DYNAMIC_CONFIG_SCAN_NODES,
            "expanded_containers": set(),
        }
        for config_path, value, parent, key in self._iter_config_nodes(config, path_prefix=path_prefix):
            if key == "_target_" and isinstance(value, str):
                self._evaluate_target(
                    value,
                    config_path,
                    config_name,
                    archive_path,
                    result,
                    parent,
                    helper_scan_state,
                    config,
                )

    def _evaluate_target(
        self,
        target: str,
        config_path: str,
        config_name: str,
        archive_path: str,
        result: ScanResult,
        target_config: dict[Any, Any] | None,
        helper_scan_state: dict[str, Any],
        config_root: Any,
    ) -> None:
        """Evaluate a single _target_ value for dangerous patterns."""
        display_target = _redact_config_evidence(target)
        display_config_path = _redact_config_evidence(config_path)
        display_config_name = _redact_config_evidence(config_name)
        callable_target = _unwrap_target_call_aliases(target)
        # Escaped interpolation openers can become active after repeated OmegaConf/Hydra resolution passes.
        if _HYDRA_INTERPOLATION_OPENER in target:
            self._add_interpolated_target_check(target, config_path, config_name, archive_path, result)
            return

        # Check against known dangerous targets (always flag, even if safe prefix)
        if _is_dangerous_callable_target(callable_target):
            result.add_check(
                name=f"{CVE_2025_23304_ID}: Dangerous Hydra _target_",
                passed=False,
                message=(
                    f"{CVE_2025_23304_ID}: Dangerous _target_ "
                    f"'{display_target}' at {display_config_path} in {display_config_name}"
                ),
                severity=IssueSeverity.CRITICAL,
                location=f"{archive_path}:{display_config_name}",
                details={
                    "target": display_target,
                    "config_path": display_config_path,
                    "config_file": display_config_name,
                    "cve_id": CVE_2025_23304_ID,
                    "cvss": CVE_2025_23304_CVSS,
                    "cwe": CVE_2025_23304_CWE,
                    "description": CVE_2025_23304_DESCRIPTION,
                    "remediation": CVE_2025_23304_REMEDIATION,
                },
                why=(
                    f"The _target_ field '{display_target}' in this NeMo "
                    f"config specifies a dangerous Python callable. "
                    f"When hydra.utils.instantiate() processes this "
                    f"config, it will execute arbitrary code "
                    f"({CVE_2025_23304_ID})."
                ),
            )
            return

        # Trusted namespaces can still hide obviously dangerous leaf names.
        if callable_target in _SAFE_TARGETS or any(
            callable_target.startswith(prefix) for prefix in _SAFE_TARGET_PREFIXES
        ):
            helper_argument = self._find_dangerous_safe_target_argument(
                callable_target,
                target_config,
                config_path,
                helper_scan_state,
                config_root,
            )
            if helper_argument is not None:
                self._add_dangerous_hydra_helper_argument_check(
                    target,
                    helper_argument["argument_name"],
                    helper_argument["argument_path"],
                    helper_argument["argument_value"],
                    helper_argument["reason"],
                    config_path,
                    config_name,
                    archive_path,
                    result,
                )
                return

            pattern = _find_suspicious_safe_prefixed_target_pattern(callable_target)
            if pattern is not None:
                self._add_suspicious_target_check(
                    target,
                    pattern,
                    config_path,
                    config_name,
                    archive_path,
                    result,
                )
                return
            result.add_check(
                name="Hydra _target_ Safety Check",
                passed=True,
                message=(f"Safe _target_ '{display_target}' at {display_config_path} in {display_config_name}"),
                location=f"{archive_path}:{display_config_name}",
                details={"target": display_target, "config_path": display_config_path},
            )
            return

        # Check for suspicious patterns in target (only for non-safe targets)
        pattern = _find_suspicious_target_pattern(callable_target)
        if pattern is not None:
            self._add_suspicious_target_check(target, pattern, config_path, config_name, archive_path, result)
            return

        # Unknown target - flag for review
        result.add_check(
            name="Hydra _target_ Review",
            passed=False,
            message=(
                f"Unknown _target_ '{display_target}' at "
                f"{display_config_path} in {display_config_name} - requires manual review"
            ),
            severity=IssueSeverity.INFO,
            location=f"{archive_path}:{display_config_name}",
            details={
                "target": display_target,
                "config_path": display_config_path,
                "config_file": display_config_name,
            },
        )

    @classmethod
    def _find_dangerous_safe_target_argument(
        cls,
        callable_target: str,
        target_config: dict[Any, Any] | None,
        config_path: str,
        helper_scan_state: dict[str, Any],
        config_root: Any,
    ) -> dict[str, str] | None:
        """Return the first unsafe helper/load argument for a safe-prefixed target."""
        if not target_config:
            return None

        dynamic_config_target = callable_target in _HYDRA_DYNAMIC_CONFIG_TARGETS
        model_load_suffix = cls._model_load_suffix(callable_target)
        model_load_argument_keys = cls._model_load_argument_keys(callable_target)
        if not (dynamic_config_target or model_load_argument_keys):
            return None

        if dynamic_config_target:
            arguments = cls._iter_dynamic_config_selector_strings(
                target_config,
                cls._target_parent_config_path(config_path),
                helper_scan_state,
                config_root,
            )
        else:
            arguments = cls._iter_direct_target_argument_strings(
                target_config,
                cls._target_parent_config_path(config_path),
                model_load_argument_keys,
                model_load_suffix,
                helper_scan_state,
                config_root,
            )

        for argument_path, argument_name, argument_value, argument_role in arguments:
            reason = cls._classify_hydra_helper_argument(
                argument_value,
                argument_name=argument_name,
                argument_role=argument_role,
                model_load_suffix=model_load_suffix,
                config_root=config_root,
            )
            if reason is not None:
                return {
                    "argument_path": argument_path,
                    "argument_name": argument_name,
                    "argument_value": argument_value,
                    "reason": reason,
                }
        return None

    @staticmethod
    def _target_parent_config_path(config_path: str) -> str:
        if config_path == "_target_":
            return ""
        suffix = "._target_"
        if config_path.endswith(suffix):
            return config_path[: -len(suffix)]
        return config_path

    @classmethod
    def _iter_direct_target_argument_strings(
        cls,
        target_config: dict[Any, Any],
        target_config_path: str,
        argument_keys: frozenset[str],
        model_load_suffix: str | None,
        helper_scan_state: dict[str, Any],
        config_root: Any,
    ) -> Iterator[tuple[str, str, str, str]]:
        positional_arguments = _MODEL_LOAD_POSITIONAL_ARGUMENTS_BY_SUFFIX.get(model_load_suffix or "", ())
        structured_config_keys = _MODEL_LOAD_STRUCTURED_CONFIG_KEYS_BY_SUFFIX.get(model_load_suffix or "", frozenset())
        for key, value in target_config.items():
            if key == "_target_":
                continue
            argument_name = str(key)
            argument_path = _append_config_path(target_config_path, argument_name)
            if argument_name in argument_keys and isinstance(value, str):
                yield argument_path, argument_name, value, "model_load_path"
            elif argument_name in structured_config_keys and isinstance(value, dict | list):
                yield from cls._iter_structured_config_argument_strings(
                    value,
                    argument_path,
                    argument_name,
                    helper_scan_state,
                    config_root,
                )
            elif argument_name == "_args_" and isinstance(value, list):
                for index, positional_name in enumerate(positional_arguments):
                    if positional_name is None or index >= len(value):
                        continue
                    positional_value = value[index]
                    if isinstance(positional_value, str):
                        yield (
                            _append_config_path(argument_path, f"[{index}]"),
                            positional_name,
                            positional_value,
                            "model_load_path",
                        )
                    elif positional_name in structured_config_keys and isinstance(positional_value, dict | list):
                        yield from cls._iter_structured_config_argument_strings(
                            positional_value,
                            _append_config_path(argument_path, f"[{index}]"),
                            positional_name,
                            helper_scan_state,
                            config_root,
                        )

    @classmethod
    def _iter_dynamic_config_selector_strings(
        cls,
        target_config: dict[Any, Any],
        target_config_path: str,
        helper_scan_state: dict[str, Any],
        config_root: Any,
    ) -> Iterator[tuple[str, str, str, str]]:
        """Yield only the value that supplies Hydra's nested config selector."""
        if "config" in target_config:
            config_value = target_config["config"]
            config_path = _append_config_path(target_config_path, "config")
            if isinstance(config_value, str):
                yield (
                    config_path,
                    "config",
                    config_value,
                    "dynamic_config_selector",
                )
            elif isinstance(config_value, dict | list):
                yield from cls._iter_structured_config_argument_strings(
                    config_value,
                    config_path,
                    "config",
                    helper_scan_state,
                    config_root,
                )
            return

        positional_values = target_config.get("_args_")
        if isinstance(positional_values, list) and positional_values:
            config_value = positional_values[0]
            config_path = _append_config_path(_append_config_path(target_config_path, "_args_"), "[0]")
            if isinstance(config_value, str):
                yield config_path, "config", config_value, "dynamic_config_selector"
            elif isinstance(config_value, dict | list):
                yield from cls._iter_structured_config_argument_strings(
                    config_value,
                    config_path,
                    "config",
                    helper_scan_state,
                    config_root,
                )

    @classmethod
    def _iter_structured_config_argument_strings(
        cls,
        value: dict[Any, Any] | list[Any],
        config_path: str,
        argument_name: str,
        helper_scan_state: dict[str, Any],
        config_root: Any,
    ) -> Iterator[tuple[str, str, str, str]]:
        """Inspect structured loader overrides once under a scan-wide budget."""
        expanded_containers = helper_scan_state["expanded_containers"]

        def walk(
            nested_value: Any,
            nested_path: str,
            depth: int,
            ancestors: frozenset[int],
            reference_chain: frozenset[str],
        ) -> Iterator[tuple[str, str, str, str]]:
            identity: int | None = None
            if isinstance(nested_value, dict | list):
                identity = id(nested_value)
                if identity in ancestors:
                    raise _NemoConfigTraversalLimit(
                        "nemo_config_recursive_alias",
                        "YAML config contains a recursive alias",
                    )
                if depth > NEMO_MAX_CONFIG_TRAVERSAL_DEPTH:
                    raise _NemoConfigTraversalLimit(
                        "nemo_config_traversal_depth_limit",
                        "YAML config exceeded the traversal depth safety limit",
                    )
                if identity in expanded_containers:
                    return

            remaining = helper_scan_state["remaining"]
            if not isinstance(remaining, int) or remaining <= 0:
                raise _NemoConfigTraversalLimit(
                    "nemo_helper_config_traversal_node_limit",
                    "Hydra helper config exceeded the traversal node safety limit",
                )
            helper_scan_state["remaining"] = remaining - 1

            if isinstance(nested_value, str):
                yield nested_path, argument_name, nested_value, "structured_config"
                match = _EXACT_SIMPLE_CONFIG_INTERPOLATION_RE.fullmatch(nested_value.strip())
                if match is not None and match.group(1) not in reference_chain:
                    referenced_value = cls._lookup_simple_config_reference(match.group(1), config_root)
                    if referenced_value is not _MISSING_CONFIG_REFERENCE:
                        yield from walk(
                            referenced_value,
                            nested_path,
                            depth + 1,
                            ancestors,
                            reference_chain | {match.group(1)},
                        )
                return
            if not isinstance(nested_value, dict | list):
                return

            assert identity is not None
            expanded_containers.add(identity)
            child_ancestors = ancestors | {identity}
            if isinstance(nested_value, dict):
                for child_key, child_value in nested_value.items():
                    yield from walk(
                        child_value,
                        _append_config_path(nested_path, str(child_key)),
                        depth + 1,
                        child_ancestors,
                        reference_chain,
                    )
            else:
                for index, child_value in enumerate(nested_value):
                    yield from walk(
                        child_value,
                        _append_config_path(nested_path, f"[{index}]"),
                        depth + 1,
                        child_ancestors,
                        reference_chain,
                    )

        yield from walk(value, config_path, 0, frozenset(), frozenset())

    @staticmethod
    def _model_load_suffix(callable_target: str) -> str | None:
        return next(
            (suffix for suffix in _MODEL_LOAD_ARGUMENT_KEYS_BY_SUFFIX if callable_target.endswith(suffix)),
            None,
        )

    @classmethod
    def _model_load_argument_keys(cls, callable_target: str) -> frozenset[str]:
        suffix = cls._model_load_suffix(callable_target)
        if suffix is None:
            return frozenset()
        return _MODEL_LOAD_ARGUMENT_KEYS_BY_SUFFIX[suffix]

    @classmethod
    def _classify_hydra_helper_argument(
        cls,
        argument_value: str,
        *,
        argument_name: str,
        argument_role: str,
        model_load_suffix: str | None,
        config_root: Any,
    ) -> str | None:
        candidate = argument_value.strip()
        if not candidate:
            return None
        if argument_role == "dynamic_config_selector" and _HYDRA_INTERPOLATION_OPENER in candidate:
            return "interpolated_helper_argument"
        if argument_role == "structured_config":
            resolved_candidate = cls._resolve_simple_config_interpolations(candidate, config_root)
            if resolved_candidate is not None:
                candidate = resolved_candidate
            elif _HYDRA_INTERPOLATION_OPENER in candidate and not _CONFIG_INTERPOLATION_RESOLVER_RE.search(candidate):
                match = _EXACT_SIMPLE_CONFIG_INTERPOLATION_RE.fullmatch(candidate)
                if (
                    match is None
                    or cls._lookup_simple_config_reference(match.group(1), config_root) is _MISSING_CONFIG_REFERENCE
                ):
                    return "interpolated_helper_argument"
            candidate_without_scalar_hydra_values = _NON_SYNTHESIZING_HYDRA_RESOLVER_RE.sub("", candidate)
            resolver_names = _CONFIG_INTERPOLATION_RESOLVER_RE.findall(candidate_without_scalar_hydra_values)
            if any(name not in _NON_SYNTHESIZING_CONFIG_RESOLVERS for name in resolver_names):
                return "interpolated_helper_argument"
            return None

        if _HYDRA_INTERPOLATION_OPENER in candidate:
            resolved_candidate = cls._resolve_simple_config_interpolations(candidate, config_root)
            if resolved_candidate is None:
                return "interpolated_helper_argument"
            candidate = resolved_candidate.strip()
            if not candidate:
                return None

        normalized_path = candidate.replace("\\", "/")
        normalized_relative_path = posixpath.normpath(normalized_path)
        escapes_relative_root = normalized_relative_path == ".." or normalized_relative_path.startswith("../")
        if model_load_suffix is not None:
            if is_absolute_archive_path(normalized_path):
                return "absolute_model_load_path"
            if model_load_suffix == ".restore_from" and normalized_path.startswith("~"):
                return "absolute_model_load_path"
            if _URI_SCHEME_RE.match(normalized_path):
                return "remote_model_load_path"
            if (
                model_load_suffix == ".from_pretrained"
                and argument_name in _MODEL_IDENTIFIER_ARGUMENTS
                and "/" in normalized_path
            ):
                return "remote_model_load_path"
            if escapes_relative_root:
                return "traversal_model_load_path"

        return None

    @staticmethod
    def _resolve_simple_config_interpolations(candidate: str, config_root: Any) -> str | None:
        """Resolve bounded root config references without evaluating OmegaConf resolvers."""
        if r"\${" in candidate or "$${" in candidate:
            return None

        current = candidate
        seen: set[str] = set()
        for _ in range(8):
            if current in seen:
                return None
            seen.add(current)
            matches = list(_SIMPLE_CONFIG_INTERPOLATION_RE.finditer(current))
            if not matches:
                return current if _HYDRA_INTERPOLATION_OPENER not in current else None

            pieces: list[str] = []
            offset = 0
            for match in matches:
                node = NemoScanner._lookup_simple_config_reference(match.group(1), config_root)
                if node is _MISSING_CONFIG_REFERENCE or not isinstance(node, str | int | float | bool | None):
                    return None
                pieces.append(current[offset : match.start()])
                pieces.append(str(node))
                offset = match.end()
            pieces.append(current[offset:])
            current = "".join(pieces)

        return None

    @staticmethod
    def _lookup_simple_config_reference(reference: str, config_root: Any) -> Any:
        node = config_root
        for path_part in reference.split("."):
            if isinstance(node, dict) and path_part in node:
                node = node[path_part]
            elif isinstance(node, list) and path_part.isdigit() and int(path_part) < len(node):
                node = node[int(path_part)]
            else:
                return _MISSING_CONFIG_REFERENCE
        return node

    def _add_dangerous_hydra_helper_argument_check(
        self,
        target: str,
        argument_name: str,
        argument_path: str,
        argument_value: str,
        reason: str,
        config_path: str,
        config_name: str,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        display_target = _redact_config_evidence(target)
        display_argument_name = _redact_config_evidence(argument_name)
        display_argument_path = _redact_config_evidence(argument_path)
        display_argument_value = _redact_config_evidence(argument_value)
        display_config_path = _redact_config_evidence(config_path)
        display_config_name = _redact_config_evidence(config_name)
        result.add_check(
            name=f"{CVE_2025_23304_ID}: Dangerous Hydra helper argument",
            passed=False,
            message=(
                f"{CVE_2025_23304_ID}: Safe-prefixed _target_ "
                f"'{display_target}' has unsafe helper argument "
                f"'{display_argument_path}' in {display_config_name}"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{display_config_name}",
            details={
                "target": display_target,
                "argument": display_argument_path,
                "argument_name": display_argument_name,
                "argument_value": display_argument_value,
                "reason": reason,
                "config_path": display_config_path,
                "config_file": display_config_name,
                "cve_id": CVE_2025_23304_ID,
                "cvss": CVE_2025_23304_CVSS,
                "cwe": CVE_2025_23304_CWE,
                "description": CVE_2025_23304_DESCRIPTION,
                "remediation": CVE_2025_23304_REMEDIATION,
            },
            why=(
                "Hydra resolves interpolated helper configs before dispatch, and model loader targets can read "
                "attacker-selected local or remote checkpoints."
            ),
        )

    def _add_interpolated_target_check(
        self,
        target: str,
        config_path: str,
        config_name: str,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        display_target = redact_evidence_string(target, max_chars=_NEMO_MAX_CONFIG_EVIDENCE_CHARS)
        display_config_path = redact_evidence_string(config_path, max_chars=_NEMO_MAX_CONFIG_EVIDENCE_CHARS)
        display_config_name = redact_evidence_string(config_name, max_chars=_NEMO_MAX_CONFIG_EVIDENCE_CHARS)
        result.add_check(
            name=f"{CVE_2025_23304_ID}: Interpolated Hydra _target_",
            passed=False,
            message=(
                f"{CVE_2025_23304_ID}: Interpolated _target_ "
                f"'{display_target}' at {display_config_path} in {display_config_name} "
                "cannot be statically verified as a safe callable"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{display_config_name}",
            details={
                "target": display_target,
                "config_path": display_config_path,
                "config_file": display_config_name,
                "cve_id": CVE_2025_23304_ID,
                "cvss": CVE_2025_23304_CVSS,
                "cwe": CVE_2025_23304_CWE,
                "description": CVE_2025_23304_DESCRIPTION,
                "remediation": CVE_2025_23304_REMEDIATION,
            },
            why=(
                "Hydra and OmegaConf can resolve interpolation expressions, including escaped forms across "
                "repeated resolution passes, before instantiating _target_. "
                "A static scan cannot prove this dynamic callable selector is safe, so the scanner fails closed."
            ),
        )

    def _add_suspicious_target_check(
        self,
        target: str,
        pattern: str,
        config_path: str,
        config_name: str,
        archive_path: str,
        result: ScanResult,
    ) -> None:
        display_target = _redact_config_evidence(target)
        display_config_path = _redact_config_evidence(config_path)
        display_config_name = _redact_config_evidence(config_name)
        result.add_check(
            name=f"{CVE_2025_23304_ID}: Suspicious Hydra _target_",
            passed=False,
            message=(
                f"{CVE_2025_23304_ID}: Suspicious _target_ "
                f"'{display_target}' (contains '{pattern}') at "
                f"{display_config_path} in {display_config_name}"
            ),
            severity=IssueSeverity.CRITICAL,
            location=f"{archive_path}:{display_config_name}",
            details={
                "target": display_target,
                "pattern": pattern,
                "config_path": display_config_path,
                "config_file": display_config_name,
                "cve_id": CVE_2025_23304_ID,
                "cvss": CVE_2025_23304_CVSS,
                "cwe": CVE_2025_23304_CWE,
                "description": CVE_2025_23304_DESCRIPTION,
                "remediation": CVE_2025_23304_REMEDIATION,
            },
        )
