import subprocess, shlex, json, os, re, uuid
SAFE_ARG = re.compile(r'^[\w\-.\\/:=+@, ]+$')
class PowerShellError(Exception): pass
class PSRunner:
    def __init__(self, shell='pwsh', execution_policy='AllSigned', timeout_sec=180, transcript_dir='logs/transcripts', configuration_name:str|None=None):
        self.shell = shell; self.execution_policy = execution_policy; self.timeout_sec = timeout_sec
        self.transcript_dir = transcript_dir; self.configuration_name = configuration_name or ''
        os.makedirs(self.transcript_dir, exist_ok=True)
    def _sanitize(self, s: str) -> str:
        if not SAFE_ARG.match(s): raise PowerShellError(f'Illegal characters in arg: {s!r}'); return s
        return s
    def run_script(self, script_path: str, args: dict|None=None, signed_only: bool=True) -> dict:
        args = args or {}; arg_str = " ".join([f"-{k} {shlex.quote(str(v))}" for k,v in args.items()])
        transcript = os.path.join(self.transcript_dir, f"ps_{uuid.uuid4().hex}.txt")
        sig_check = f"$sig = Get-AuthenticodeSignature -FilePath '{script_path}'; if ($sig.Status -ne 'Valid') {{ if ({'$true' if signed_only else '$false'}) {{ Write-Error 'Signature not Valid'; exit 3 }} }};"
        inner = f"$t='{transcript}'; Start-Transcript -Path $t -Append; {sig_check} & '{script_path}' {arg_str}; Stop-Transcript"
        if self.configuration_name:
            cmd = [self.shell,"-NoLogo","-NoProfile","-ExecutionPolicy",self.execution_policy,"-Command",
                   f"Invoke-Command -ComputerName localhost -ConfigurationName {self.configuration_name} -ScriptBlock {{ {inner} }}"]
        else:
            cmd = [self.shell,"-NoLogo","-NoProfile","-ExecutionPolicy",self.execution_policy,"-Command", inner]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_sec)
        except subprocess.TimeoutExpired:
            raise PowerShellError(f"Timeout after {self.timeout_sec}s")
        if proc.returncode != 0:
            raise PowerShellError(proc.stderr.strip() or f"PowerShell failed: {proc.returncode}")
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        payload = lines[-1] if lines else "{}"
        try: data = json.loads(payload)
        except Exception: data = {"raw": proc.stdout}
        data["_meta"] = {"script": script_path, "transcript": transcript, "jea": bool(self.configuration_name)}
        return data
