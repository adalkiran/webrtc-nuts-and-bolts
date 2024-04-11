#!/bin/sh

set -e

cd mkdocs
rm -rf docs && mkdir -p docs
cp -r ../*.md ../images ./stylesheets ./javascripts ./assets ./docs

rm ./docs/README.md
cp ./extra-content/*.md ./docs

GITHUB_URL="https://github.com/adalkiran/webrtc-nuts-and-bolts"

GITHUB_CONTENT_PREFIX="$GITHUB_URL/blob/main"

nav_items=""

for file in ./docs/*.md; do

    # Remove footer navigation
    sed -i -e ':a;N;$!ba; s/\s*<br>\s*---*.*//g; ta' "$file"

    # Edit same level paths
    sed -i -e 's/\](\.\//\](/g' "$file"

    # Edit upper level paths
    sed -i -e "s,\(\[[^\[]*\]\)(\.\.\/\([^)]*\)),\1($GITHUB_CONTENT_PREFIX\/\2),g" "$file"
    sed -i -e "s,\(\[.*\]\)(\.\.\/\([^)]*\)),\1($GITHUB_CONTENT_PREFIX\/\2),g" "$file"
    sed -i -e "s,\(\[.*\]\)(\([^)]*\.ipynb\)),\1($GITHUB_CONTENT_PREFIX\/docs\/\2),g" "$file"

    # Edit img tag paths
    sed -i -e 's/src="images\//src="..\/images\//g' "$file"

    # Edit external links
    sed -i -e "/\!\[/!s,\[\([^\[]*\)\](http\([^)]*\)),\<a href=\"http\2\" target=\"_blank\"\>\1\<\/a\>,g" "$file"
    sed -i -e "/\!\[/!s,\[\(.*\)\](http\([^)]*\)),\<a href=\"http\2\" target=\"_blank\"\>\1\<\/a\>,g" "$file"

    file_name=$(basename "$file")
    first_line=$(head -1 "$file")
    title=$(echo "$first_line" | sed -e 's/^[^\.]*\. \(.*\)\*\*/\1/g')
    chapter_num=$(echo "$first_line" | sed -e 's/^[^0-9]*\([0-9]*\)\..*/\1/g')
    case $first_line in
        "---"*)
            nav_items="\n    - '$file_name'${nav_items}"
            ;;
        *)
            if [ ${#chapter_num} -lt 3 ]; then
                chapter_num=$(expr $chapter_num + 1)
                nav_items="${nav_items}\n    - '$file_name'"
            else
                chapter_num=0
                nav_items="\n    - '$file_name'${nav_items}"
            fi
            echo "---
title: $title
type: docs
menus:
  - main
weight: $chapter_num
---
" | cat - "$file" > temp && mv temp "$file"
            ;;
    esac
done

cat mkdocs.yml.template | sed -e "s/{{navigation_placeholder}}/${nav_items}/g" > mkdocs.yml
