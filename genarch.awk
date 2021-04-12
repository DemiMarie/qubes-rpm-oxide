BEGIN {
    FS = "[[:space:]:]+"
    RS = "\n"
    for (i in ARGV) { if (substr(ARGV[i], 1, 1) != "/") { ARGV[i] = ("./" ARGV[i]) } }
    current_os = 1
    current_arch = 1
    arch[0] = ("// GENERATED by genarch.awk, do not edit\n\n"\
               "use std::ascii::AsciiExt;\n"\
               "fn arch_to_archnum(arch: &[u8]) -> Option<u16> {\n"\
               "    match &arch.to_ascii_lowercase()[..] {\n"\
               "        b\"noarch\" => Some(255),")
    os[0] = "fn os_to_osnum(os: &[u8]) -> Option<u16> {\n    match &os.to_ascii_lowercase()[..] {"
}

function add_arch(key, value) {
    key = tolower(key)
    s = seen[$1 ":" key]
    if (s) {
        if (s != value + 1) {
            # Work around a Fedora 33 rpmrc bug
            if ($1 == "os_canon" && key == "cygwin32")
                next
            print("ERROR: ambiguous entries in rpmrc for key " $1 ":" key)>"/dev/stderr"
            bad = 1
        }
        next
    }
    seen[$1 ":" key] = value + 1
    to_emit = ("        b\"" key "\" => Some(" value "),")
    if ($1 == "arch_canon") {
        arch[current_arch++] = to_emit
    } else if ($1 == "os_canon") {
        os[current_os++] = to_emit
    } else {
        print "INTERNAL ERROR: internal wrong $1">"/dev/stderr"
        bad = 1
        exit 1
    }
}

/^(#|[[:space:]]*$)/ {next}
/^(arch|os)_canon(:[[:space:]]+[0-9A-Za-z_-]+){2}[[:space:]]+[1-9][0-9]*$/ {
    add_arch($2, $4)
    add_arch($3, $4)
}

END {
    if (bad)
        exit 1
    for (i in arch)
        print(arch[i])
    print "        _ => None,\n    }\n}\n"
    for (i in os)
        print(os[i])
    print "        _ => None,\n    }\n}"
}
