#!/bin/bash

last_sunday () {
  date -v-sunday +'%Y-%m-%d';
}

for user in $(aws iam list-users --query 'Users[?(CreateDate <= `$last_sunday` && (PasswordLastUsed <= `2021-12-26`) || !not_null(PasswordLastUsed))].UserName' --output text); do
    for access_key in $(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do if [[ "$(aws iam get-access-key-last-used --access-key-id "$access_key" --query 'AccessKeyLastUsed.LastUsedDate >= `2022-02-09`' --output text)" == True ]]; then continue 2; fi; done
    echo "$user"
done
