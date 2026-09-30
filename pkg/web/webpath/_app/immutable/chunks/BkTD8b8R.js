const n=`A Security Tool for Bug Bounty, Pentest and Red Teaming.

## Installation

### Prerequisites

- [Go](https://go.dev/) version 1.19 or higher.

you can install it with:

\`\`\`sh [Binary]
https://github.com/zan8in/afrog/releases
\`\`\`

\`\`\`sh [Github]
git clone https://github.com/zan8in/afrog.git
cd afrog
go mod tidy
go build -o afrog cmd/afrog/main.go
./afrog -h
\`\`\`

\`\`\`sh [Go]
go install -v https://github.com/zan8in/afrog/cmd/afrog@latest
\`\`\`

## Running afrog

By default, afrog scans all built-in PoCs, and if it finds any vulnerabilities, it automatically creates an HTML report with the date of the scan as the filename.

\`\`\`sh
afrog -t https://example.com
\`\`\`

_**details Warning occurs when running afrog**_
_**If you see an error message saying:**_
\`\`\`
[ERR] ceye reverse service not set: /home/afrog/.config/afrog/afrog-config.yaml
\`\`\`
it means you need to modify the [configuration file](https://github.com/zan8in/afrog/wiki/Configuration#rerverse).


To execute a custom PoC directory, you can use the following command:

\`\`\`sh
afrog -t https://example.com -P mypocs/
\`\`\`

You can scan multiple URLs at the same time as well.

\`\`\`sh
afrog -T urls.txt
\`\`\`

For more information on how to use the tool, please refer to the usage documentation ([Usage](https://github.com/zan8in/afrog/wiki/Usage#filters)).`;export{n as default};
