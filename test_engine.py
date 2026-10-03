from organisation_data import ORGANISATION, TRUSTED_IDENTITIES


print("Organisation:")
print(ORGANISATION["name"])

print("\nOfficial domains:")
for domain in ORGANISATION["official_domains"]:
    print("-", domain)

print("\nTrusted identities:")

for identity in TRUSTED_IDENTITIES:
    print(
        f'- {identity["name"]} | '
        f'{identity["role"]} | '
        f'{identity["email"]}'
    )
