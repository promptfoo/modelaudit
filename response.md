Hi Aakash,

Happy Friday, and thanks for the detailed questions. ModelAudit supports 296 checks across all ML model formats.

1. Code Execution Detection

ModelAudit detects code execution through several methods:

- Pickle opcode analysis: We examine REDUCE, INST, OBJ, NEWOBJ patterns that enable code execution via object instantiation
- Raw byte scanning: Before parsing, we scan for patterns like posix, subprocess, **import** to catch payloads in corrupted files
- Nested payloads: We detect base64/hex encoded pickles within pickles
- Template injection: ModelAudit flags Jinja2 patterns in model metadata. While we catch most template injection attempts, deeply nested or obfuscated calls may require additional analysis. I'm building a test case for this. If you have a sample model, I'd be interested in testing it. Happy to send you our list of known malicious models for testing as well.

2. Pickle Analysis Depth

When we flag opcodes like REDUCE, INST, OBJ, or NEWOBJ:

- REDUCE: We track the callable and its arguments. REDUCE with os.system is flagged as critical, while REDUCE with torch.nn.Module is considered safe in ML contexts
- INST/OBJ/NEWOBJ: We analyze the class being instantiated and check if **init** methods could trigger code execution
- STACK_GLOBAL: We reconstruct the full module.function reference from the stack to identify calls like posix.system or subprocess.Popen

For patterns like 'posix':

- We analyze opcode context, not just the string. A 'posix' string in data is different from GLOBAL posix system followed by REDUCE
- We track the chain: posix module import → system function reference → REDUCE opcode = critical command execution vulnerability
- We detect obfuscation attempts where posix.system might be built dynamically through string concatenation or base64 decoding

Our ML context awareness distinguishes between normal PyTorch tensor operations (which use REDUCE extensively) and actual exploitation attempts, reducing false positives.

3. Large/Compressed Files

You can adjust limits for the models you mentioned:

modelaudit scan --timeout 1800 large_model.bin # 30-minute timeout
modelaudit scan --max-file-size 10737418240 model.bin # 10GB limit

Streaming analysis for larger files is included in version 0.2.1.

4. Configuration Patterns

The truncation_side warning is a false positive we're addressing. ModelAudit's pattern matching sometimes incorrectly flags legitimate NLP parameters like truncation_side, padding_side, and decoder_start_token_id. We maintain allowlists for known-safe patterns and can easily add your model's configuration. These are informational warnings, not critical issues.

5. Remote Model Scanning

ModelAudit currently downloads models locally before scanning. We can discuss your disk space constraints and potential workarounds on Monday.

6. File Format Support

Core formats:

- Pickle variants: .pkl, .pickle, .joblib, .dill
- PyTorch: .pt, .pth, .bin, .ckpt
- TensorFlow: SavedModel, .pb, .h5
- ONNX: .onnx
- SafeTensors: .safetensors
- GGUF/GGML: .gguf, .ggml
- Archives: .zip, .tar, .tar.gz, .tar.bz2

Additional formats with dependencies:

- Flax/JAX: .msgpack (install with: pip install modelaudit[flax])
- CoreML: .mlmodel, .mlpackage
- TensorRT: .engine, .plan

7. Comparative Analysis

ModelAudit 0.2.1 does detect **builtin**.eval as critical. Our ML context might adjust severity if it's surrounded by legitimate model patterns. We optimize for actionable findings rather than overwhelming alerts, but we don't miss critical execution vectors like eval.

Next Steps

I just released ModelAudit 0.2.1 (https://pypi.org/project/modelaudit/0.2.1/) with improvements to pickle scanning and false positive reduction. Please try it - it may address some issues you've encountered.

Let's go through your specific models on Monday's call. Bring any examples with unexpected results.

Best regards,
Michael

On Thu, Aug 14, 2025 at 6:22 PM Ian Webster <ian@promptfoo.dev> wrote:
Hi Aakash,

I'm cc'ing Michael on this thread who is our static scanning expert - he can help address these questions!

Ian

On Thu, Aug 14, 2025 at 3:18 PM, Patel, Aakash Xsell Resources, Inc. <Aakash.Patel3@cvshealth.com> wrote:
Hey Ian,
We're continuing our evaluation of Promptfoo ModelAudit and have a few questions about its capabilities and how it handles certain scenarios, building on our earlier interactions. We're trying to get a clearer picture of its strengths for our use cases.
Specifically, we're interested in understanding:
Code Execution Detection: Beyond direct `exec` and `eval` calls, how does Promptfoo analyze for potential code execution risks embedded within templating languages (like Jinja) or through indirect mechanisms like Python object serialization (e.g., pickle)? Are there specific analysis techniques employed to uncover these more subtle execution vectors?
Pickle File Analysis Granularity: When Promptfoo identifies "Suspicious opcode sequences" or "Dangerous patterns" within pickle files, can you elaborate on the depth of this analysis? For instance, if opcodes like `REDUCE`, `INST`, `OBJ`, or `NEWOBJ` are flagged, what is the typical interpretation of these patterns in terms of exploitable vulnerabilities (e.g., deserialization attacks)? Similarly, when patterns like 'posix' are detected, is there an analysis of how these might be leveraged for system calls like `os.system` or `os.popen`?
Handling Large/Compressed Files: We've encountered situations where scans might be limited by ZIP entry size constraints. Could you clarify if there's flexibility in adjusting such limits, or if Promptfoo supports alternative methods for handling larger compressed archives? We've noticed issues with models like `ykilcher_totally-harmless-model` and `drhyrum--bert-ty-financial-news-sentiment` in this regard.
Configuration Pattern Insights: For specific configuration directives, such as `truncation_side` (as seen in `Alibaba-NLP_gte-large-en-v1.5`), what is the underlying rationale for flagging them as potentially suspicious in an execution context?
Remote Model Scanning Efficiency: When scanning remote models, is there a possibility to perform analysis directly from mounted cloud storage buckets, rather than requiring local disk loading? We're mindful of potential disk space constraints on compute environments.
File Format Support: We've encountered challenges with Promptfoo ModelAudit's handling of formats like .msgpack and .zip during our testing. Could you clarify what the current range of natively supported model file formats is?
Comparative Analysis: We've observed that different security scanning tools can produce varying results, with some flagging vulnerabilities that Promptfoo might not, or vice-versa. For example, we analyzed a model that we believe to be malicious (e.g., containing an `eval` operator from `__builtin__`), but Promptfoo did not flag it with the same severity as other tools. Could you provide insight into why Promptfoo might have a different assessment in such cases, or if there are specific types of risks it is designed to prioritize or de-prioritize.
Please let us know if you're able to address these questions or if there's a resource that might offer more detail.

Best Regards,

Aakash Patel
