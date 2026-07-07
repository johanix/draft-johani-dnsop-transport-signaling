# draft-johani-dnsop-transport-signaling



## Building

Requires [kramdown-rfc](https://github.com/cabo/kramdown-rfc) and
[xml2rfc](https://github.com/ietf-tools/xml2rfc).

```sh
make        # build .txt and .html from the .md source
make txt    # text rendering only
make html   # HTML rendering only
make xml    # just the xml2rfc v3 XML
make clean  # remove generated files
```

The Markdown source (`draft-johani-dnsop-transport-signaling-0*.md`) is the
canonical document; the `.xml`, `.txt`, and `.html` files are
generated from it.