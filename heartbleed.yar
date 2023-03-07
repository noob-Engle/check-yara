rule Heartbleed {
    strings:
        $heartbleedz = { 18 03 02 00 03 }
        $payload = /(?:00|ff){16,}/
    condition:
        $heartbleedz and $payload
}
