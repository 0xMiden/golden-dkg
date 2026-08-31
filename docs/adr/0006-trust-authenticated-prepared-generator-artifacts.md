# Trust authenticated prepared-generator artifacts

Deployment owns storage and authentication of prepared-generator artifacts. Restoration validates canonical encoding, curve points, declared capacity, and exact logical length, but does not rederive and compare the deterministic generator prefix because doing so would defeat persisted preparation; unauthenticated artifact loading is outside Golden's persistence threat model.
