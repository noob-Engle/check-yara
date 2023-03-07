rule Base64EncodedPythonReverseShell {
    meta:
        description = "detects base64 encoded python reverse shell"
    strings:
//查找字符串“base64.b64decode”和“subprocess.Popen”，这些字符串通常用于在 python 中编码和执行反向 shell
        $encoded = "base64.b64decode"
        $reverse_shell = "subprocess.Popen"
    condition:
        all of them
}
