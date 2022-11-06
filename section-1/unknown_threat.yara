rule unknown_threat {
    meta:
        Author = "@ubuntu"
        Description = "rule detects the presence of any files coming from 'darkl0rd'"
    strings:
        $url1 = /.*(darkl0rd).*/
    condition:
        any of them
}
