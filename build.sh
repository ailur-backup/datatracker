#!/bin/sh

path=$(realpath "$(dirname "$0")") || exit 1
resourceDir="$path/../../resources/322dc186-04d2-4f69-89b5-403ab643cc1d"
rm -rf "$resourceDir" || exit 1
rm -rf "$path/../../services/data-tracker.fgs" || exit 1
cd "$path" || exit 1
go build -o "$path/../../services/data-tracker.fgs" --buildmode=plugin -ldflags "-s -w" || exit 1
cd "$path/resources/wasm/oauth" || exit 1
GOOS=js GOARCH=wasm go build -o "$resourceDir/static/wasm/oauth.wasm" -ldflags "-s -w" || exit 1
cp -r "$path/resources/static" "$resourceDir/" || exit 1
cp -r "$path/resources/templates" "$resourceDir/" || exit 1
