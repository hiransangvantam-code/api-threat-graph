# Findings that match no planted weakness (v1.3)

Each one needs a reading: a true weakness that was not planted (the baseline was not as clean as meant), a consequence of a planted one, or a false alarm.


## PayNow (23)

Endpoints missed: none  
Endpoints listed that do not exist: ep:auth-service:POST:/session, ep:merchant-service:GET:/{}, ep:merchant-service:GET:/{}/settlements, ep:transfer-service:GET:/{}, ep:transfer-service:POST:/, ep:wallet-service:GET:/{}, ep:wallet-service:GET:/{}/statement, ep:wallet-service:POST:/{}/topup

- **API3** `ep:merchant-service:GET:/{}/settlements`: GET /{id}/settlements (merchant-service) returns a list with financial fields
- **API3** `ep:wallet-service:GET:/{}/statement`: GET /{id}/statement (wallet-service) returns a list with financial fields
- **TS-01** `ep:auth-service:POST:/session`: POST /session (auth-service) returned 2xx to 14 request(s) without a token
- **API1** `ep:wallet-service:GET:/{}/statement`: GET /{id}/statement (wallet-service): object ID from path, response carries owner field owner_id, 0 x 403 in 0 calls
- **API9-SHADOW** `ep:transfer-service:GET:/{}`: GET /{id} (transfer-service) is served but in no spec
- **API9-SHADOW** `ep:wallet-service:GET:/{}`: GET /{id} (wallet-service) is served but in no spec
- **API9-SHADOW** `ep:merchant-service:GET:/{}/settlements`: GET /{id}/settlements (merchant-service) is served but in no spec
- **API9-SHADOW** `ep:wallet-service:GET:/{}/statement`: GET /{id}/statement (wallet-service) is served but in no spec
- **TS-02** `svc:kong`: route /api/auth/** -> auth-service has auth: none
- **API9-SHADOW** `ep:merchant-service:GET:/{}`: GET /{id} (merchant-service) is served but in no spec
- **API9-SHADOW** `ep:transfer-service:POST:/`: POST / (transfer-service) is served but in no spec
- **API9-SHADOW** `ep:auth-service:POST:/session`: POST /session (auth-service) is served but in no spec
- **API9-SHADOW** `ep:wallet-service:POST:/{}/topup`: POST /{id}/topup (wallet-service) is served but in no spec
- **API1** `ep:ledger-service:GET:/ledger/accounts/{}/balance`: GET /ledger/accounts/{account_id}/balance (ledger-service): object ID from path, response carries owner field account_id, 0 x 403 in 60 calls
- **LT-04** `ep:transfer-service:POST:/`: POST / (transfer-service): 1 x 5xx, 0 error spans
- **LT-03** `ep:merchant-service:GET:/{}`: GET /{id} (merchant-service): 47 requests, 0 spans
- **LT-03** `ep:transfer-service:GET:/{}`: GET /{id} (transfer-service): 57 requests, 0 spans
- **LT-03** `ep:wallet-service:GET:/{}`: GET /{id} (wallet-service): 72 requests, 0 spans
- **LT-03** `ep:merchant-service:GET:/{}/settlements`: GET /{id}/settlements (merchant-service): 58 requests, 0 spans
- **LT-03** `ep:wallet-service:GET:/{}/statement`: GET /{id}/statement (wallet-service): 62 requests, 0 spans
- **LT-03** `ep:transfer-service:POST:/`: POST / (transfer-service): 46 requests, 0 spans
- **LT-03** `ep:auth-service:POST:/session`: POST /session (auth-service): 34 requests, 0 spans
- **LT-03** `ep:wallet-service:POST:/{}/topup`: POST /{id}/topup (wallet-service): 50 requests, 0 spans

## CareLink (1)

- **TS-03** `ep:records-service:GET:/records/{}/pdf`: spec requires auth for GET /records/{record_id}/pdf (records-service), but 40 requests without a token succeeded

## SkyFly (0)


## FleetGo (27)

Endpoints missed: none  
Endpoints listed that do not exist: ep:ingress-gateway:GET:/api/drivers/{}, ep:ingress-gateway:GET:/api/shipments/{}, ep:ingress-gateway:GET:/api/shipments/{}/label, ep:ingress-gateway:GET:/api/tracking/debug/pprof/goroutine, ep:ingress-gateway:GET:/api/tracking/{}, ep:ingress-gateway:GET:/api/tracking/{}/history, ep:ingress-gateway:PATCH:/api/drivers/{}/status, ep:ingress-gateway:POST:/api/auth/session, ep:ingress-gateway:POST:/api/shipments

- **LT-01** `svc:ingress-gateway`: 50 trace(s) start at ingress-gateway GET /api/drivers/** with no traced caller
- **LT-01** `svc:ingress-gateway`: 133 trace(s) start at ingress-gateway GET /api/shipments/** with no traced caller
- **LT-01** `svc:ingress-gateway`: 150 trace(s) start at ingress-gateway GET /api/tracking/** with no traced caller
- **LT-01** `svc:ingress-gateway`: 55 trace(s) start at ingress-gateway PATCH /api/drivers/** with no traced caller
- **LT-01** `svc:ingress-gateway`: 34 trace(s) start at ingress-gateway POST /api/auth/** with no traced caller
- **LT-01** `svc:ingress-gateway`: 44 trace(s) start at ingress-gateway POST /api/shipments/** with no traced caller
- **API9-SHADOW** `ep:ingress-gateway:GET:/api/drivers/{}`: GET /api/drivers/{id} (ingress-gateway) is served but in no spec
- **API9-SHADOW** `ep:ingress-gateway:GET:/api/shipments/{}`: GET /api/shipments/{id} (ingress-gateway) is served but in no spec
- **TS-07** `ep:ingress-gateway:POST:/api/auth/session`: POST /api/auth/session (ingress-gateway): 20 failed logins, no 429 seen
- **TS-07** `ep:auth-service:POST:/auth/session`: POST /auth/session (auth-service): 20 failed logins, no 429 seen
- **API9-SHADOW** `ep:ingress-gateway:GET:/api/shipments/{}/label`: GET /api/shipments/{id}/label (ingress-gateway) is served but in no spec
- **API9-SHADOW** `ep:ingress-gateway:GET:/api/tracking/debug/pprof/goroutine`: GET /api/tracking/debug/pprof/goroutine (ingress-gateway) is served but in no spec
- **API9-SHADOW** `ep:ingress-gateway:GET:/api/tracking/{}`: GET /api/tracking/{id} (ingress-gateway) is served but in no spec
- **API9-SHADOW** `ep:ingress-gateway:GET:/api/tracking/{}/history`: GET /api/tracking/{id}/history (ingress-gateway) is served but in no spec
- **API9-SHADOW** `ep:ingress-gateway:PATCH:/api/drivers/{}/status`: PATCH /api/drivers/{id}/status (ingress-gateway) is served but in no spec
- **API9-SHADOW** `ep:ingress-gateway:POST:/api/auth/session`: POST /api/auth/session (ingress-gateway) is served but in no spec
- **API9-SHADOW** `ep:ingress-gateway:POST:/api/shipments`: POST /api/shipments (ingress-gateway) is served but in no spec
- **API9-NOSPEC** `svc:ingress-gateway`: ingress-gateway: no live spec; 0 of 9 endpoints documented anywhere
- **LT-03** `ep:ingress-gateway:GET:/api/drivers/{}`: GET /api/drivers/{id} (ingress-gateway): 50 requests, 0 spans
- **LT-03** `ep:ingress-gateway:GET:/api/shipments/{}`: GET /api/shipments/{id} (ingress-gateway): 77 requests, 0 spans
- **LT-03** `ep:ingress-gateway:GET:/api/shipments/{}/label`: GET /api/shipments/{id}/label (ingress-gateway): 56 requests, 0 spans
- **LT-03** `ep:ingress-gateway:GET:/api/tracking/debug/pprof/goroutine`: GET /api/tracking/debug/pprof/goroutine (ingress-gateway): 20 requests, 0 spans
- **LT-03** `ep:ingress-gateway:GET:/api/tracking/{}`: GET /api/tracking/{id} (ingress-gateway): 75 requests, 0 spans
- **LT-03** `ep:ingress-gateway:GET:/api/tracking/{}/history`: GET /api/tracking/{id}/history (ingress-gateway): 55 requests, 0 spans
- **LT-03** `ep:ingress-gateway:PATCH:/api/drivers/{}/status`: PATCH /api/drivers/{id}/status (ingress-gateway): 55 requests, 0 spans
- **LT-03** `ep:ingress-gateway:POST:/api/auth/session`: POST /api/auth/session (ingress-gateway): 34 requests, 0 spans
- **LT-03** `ep:ingress-gateway:POST:/api/shipments`: POST /api/shipments (ingress-gateway): 44 requests, 0 spans

## LearnHub (0)


## StreamBox (18)

- **API3** `ep:billing-service:GET:/billing/invoices`: GET /billing/invoices (billing-service) returns a list with financial fields
- **TS-01** `ep:billing-service:GET:/billing/invoices`: GET /billing/invoices (billing-service) returned 2xx to 40 request(s) without a token
- **TS-01** `ep:billing-service:GET:/billing/invoices/{}`: GET /billing/invoices/{invoice_id} (billing-service) returned 2xx to 40 request(s) without a token
- **TS-01** `ep:profile-service:GET:/profiles/{}`: GET /profiles/{profile_id} (profile-service) returned 2xx to 40 request(s) without a token
- **TS-01** `ep:billing-service:POST:/billing/payment-methods`: POST /billing/payment-methods (billing-service) returned 2xx to 20 request(s) without a token
- **TS-01** `ep:catalog-service:POST:/titles/{}/playback`: POST /titles/{title_id}/playback (catalog-service) returned 2xx to 56 request(s) without a token
- **TS-01** `ep:profile-service:PUT:/profiles/{}/preferences`: PUT /profiles/{profile_id}/preferences (profile-service) returned 2xx to 40 request(s) without a token
- **TS-03** `ep:billing-service:GET:/billing/invoices`: spec requires auth for GET /billing/invoices (billing-service), but 40 requests without a token succeeded
- **TS-03** `ep:profile-service:GET:/profiles/{}`: spec requires auth for GET /profiles/{profile_id} (profile-service), but 40 requests without a token succeeded
- **TS-03** `ep:catalog-service:GET:/titles`: spec requires auth for GET /titles (catalog-service), but 60 requests without a token succeeded
- **TS-03** `ep:catalog-service:GET:/titles/{}`: spec requires auth for GET /titles/{title_id} (catalog-service), but 40 requests without a token succeeded
- **TS-03** `ep:catalog-service:POST:/titles/{}/playback`: spec requires auth for POST /titles/{title_id}/playback (catalog-service), but 56 requests without a token succeeded
- **TS-03** `ep:profile-service:PUT:/profiles/{}/preferences`: spec requires auth for PUT /profiles/{profile_id}/preferences (profile-service), but 40 requests without a token succeeded
- **TS-01** `ep:drm-service:POST:/licenses`: POST /licenses (drm-service) returned 2xx to 60 request(s) without a token
- **TS-03** `ep:recommendation-service:GET:/recommendations/{}`: spec requires auth for GET /recommendations/{title_id} (recommendation-service), but 56 requests without a token succeeded
- **TS-03** `ep:drm-service:POST:/licenses`: spec requires auth for POST /licenses (drm-service), but 60 requests without a token succeeded
- **TS-08** `ep:recommendation-service:GET:/recommendations/{}`: catalog-service -> GET /recommendations/{title_id} (recommendation-service) with no credential
- **TS-08** `ep:drm-service:POST:/licenses`: catalog-service -> POST /licenses (drm-service) with no credential

## CityGov (0)


## FoodDash (19)

Endpoints missed: none  
Endpoints listed that do not exist: ep:order-service:GET:ders/{}, ep:order-service:GET:ders/{}/receipt, ep:order-service:POST:ders, ep:payment-service:GET:ents/{}, ep:restaurant-service:GET:ants, ep:restaurant-service:GET:ants/{}/menu, ep:rider-service:GET:ders/nearby

- **API1** `ep:order-service:GET:ders/{}/receipt`: GET ders/{id}/receipt (order-service): object ID from path, response carries owner field customer_id, 0 x 403 in 0 calls
- **API9-SHADOW** `ep:order-service:GET:ders/{}`: GET ders/{id} (order-service) is served but in no spec
- **API9-SHADOW** `ep:order-service:GET:ders/{}/receipt`: GET ders/{id}/receipt (order-service) is served but in no spec
- **API9-SHADOW** `ep:payment-service:GET:ents/{}`: GET ents/{id} (payment-service) is served but in no spec
- **TS-02** `svc:mesh-gateway`: route /api/orders/** -> order-service has auth: unspecified
- **TS-02** `svc:mesh-gateway`: route /api/payments/** -> payment-service has auth: unspecified
- **TS-02** `svc:mesh-gateway`: route /api/restaurants/** -> restaurant-service has auth: unspecified
- **TS-02** `svc:mesh-gateway`: route /api/riders/** -> rider-service has auth: unspecified
- **API9-SHADOW** `ep:restaurant-service:GET:ants`: GET ants (restaurant-service) is served but in no spec
- **API9-SHADOW** `ep:restaurant-service:GET:ants/{}/menu`: GET ants/{id}/menu (restaurant-service) is served but in no spec
- **API9-SHADOW** `ep:rider-service:GET:ders/nearby`: GET ders/nearby (rider-service) is served but in no spec
- **API9-SHADOW** `ep:order-service:POST:ders`: POST ders (order-service) is served but in no spec
- **LT-03** `ep:restaurant-service:GET:ants`: GET ants (restaurant-service): 66 requests, 0 spans
- **LT-03** `ep:restaurant-service:GET:ants/{}/menu`: GET ants/{id}/menu (restaurant-service): 49 requests, 0 spans
- **LT-03** `ep:rider-service:GET:ders/nearby`: GET ders/nearby (rider-service): 45 requests, 0 spans
- **LT-03** `ep:order-service:GET:ders/{}`: GET ders/{id} (order-service): 57 requests, 0 spans
- **LT-03** `ep:order-service:GET:ders/{}/receipt`: GET ders/{id}/receipt (order-service): 53 requests, 0 spans
- **LT-03** `ep:payment-service:GET:ents/{}`: GET ents/{id} (payment-service): 58 requests, 0 spans
- **LT-03** `ep:order-service:POST:ders`: POST ders (order-service): 64 requests, 0 spans

## InsureCo (0)


## TeleMax (35)

Endpoints missed: none  
Endpoints listed that do not exist: ep:auth-service:POST:/api/auth/session, ep:billing-service:GET:/api/bills/{}, ep:billing-service:POST:/api/bills/{}/pay, ep:device-service:GET:/api/devices/{}, ep:number-porting-service:GET:/api/porting/{}, ep:number-porting-service:POST:/api/porting, ep:plan-service:GET:/api/plans, ep:plan-service:GET:/api/plans/{}, ep:sim-service:POST:/api/sims/{}/swap, ep:subscriber-service:GET:/api/subscribers/{}, ep:subscriber-service:PATCH:/api/subscribers/{}, ep:support-service:GET:/api/tickets/search, ep:support-service:GET:/api/tickets/{}, ep:support-service:POST:/api/tickets, ep:usage-service:GET:/api/usage/{}, ep:usage-service:GET:/api/usage/{}/cdr

- **API1** `ep:usage-service:GET:/api/usage/{}/cdr`: GET /api/usage/{id}/cdr (usage-service): object ID from path, response carries owner field user_id, 0 x 403 in 0 calls
- **API9-SHADOW** `ep:billing-service:GET:/api/bills/{}`: GET /api/bills/{id} (billing-service) is served but in no spec
- **API9-SHADOW** `ep:subscriber-service:GET:/api/subscribers/{}`: GET /api/subscribers/{id} (subscriber-service) is served but in no spec
- **API9-SHADOW** `ep:billing-service:POST:/api/bills/{}/pay`: POST /api/bills/{id}/pay (billing-service) is served but in no spec
- **API9-SHADOW** `ep:device-service:GET:/api/devices/{}`: GET /api/devices/{id} (device-service) is served but in no spec
- **API9-SHADOW** `ep:plan-service:GET:/api/plans`: GET /api/plans (plan-service) is served but in no spec
- **API9-SHADOW** `ep:plan-service:GET:/api/plans/{}`: GET /api/plans/{id} (plan-service) is served but in no spec
- **API9-SHADOW** `ep:number-porting-service:GET:/api/porting/{}`: GET /api/porting/{id} (number-porting-service) is served but in no spec
- **API9-SHADOW** `ep:support-service:GET:/api/tickets/search`: GET /api/tickets/search (support-service) is served but in no spec
- **API9-SHADOW** `ep:support-service:GET:/api/tickets/{}`: GET /api/tickets/{id} (support-service) is served but in no spec
- **API9-SHADOW** `ep:usage-service:GET:/api/usage/{}`: GET /api/usage/{id} (usage-service) is served but in no spec
- **API9-SHADOW** `ep:usage-service:GET:/api/usage/{}/cdr`: GET /api/usage/{id}/cdr (usage-service) is served but in no spec
- **API9-SHADOW** `ep:subscriber-service:PATCH:/api/subscribers/{}`: PATCH /api/subscribers/{id} (subscriber-service) is served but in no spec
- **API9-SHADOW** `ep:auth-service:POST:/api/auth/session`: POST /api/auth/session (auth-service) is served but in no spec
- **API9-SHADOW** `ep:number-porting-service:POST:/api/porting`: POST /api/porting (number-porting-service) is served but in no spec
- **API9-SHADOW** `ep:sim-service:POST:/api/sims/{}/swap`: POST /api/sims/{id}/swap (sim-service) is served but in no spec
- **API9-SHADOW** `ep:support-service:POST:/api/tickets`: POST /api/tickets (support-service) is served but in no spec
- **TS-07** `ep:auth-service:POST:/auth/session`: POST /auth/session (auth-service): 15 failed logins, no 429 seen
- **LT-04** `ep:sim-service:POST:/api/sims/{}/swap`: POST /api/sims/{id}/swap (sim-service): 1 x 5xx, 0 error spans
- **LT-03** `ep:billing-service:GET:/api/bills/{}`: GET /api/bills/{id} (billing-service): 39 requests, 0 spans
- **LT-03** `ep:device-service:GET:/api/devices/{}`: GET /api/devices/{id} (device-service): 44 requests, 0 spans
- **LT-03** `ep:plan-service:GET:/api/plans`: GET /api/plans (plan-service): 52 requests, 0 spans
- **LT-03** `ep:plan-service:GET:/api/plans/{}`: GET /api/plans/{id} (plan-service): 35 requests, 0 spans
- **LT-03** `ep:number-porting-service:GET:/api/porting/{}`: GET /api/porting/{id} (number-porting-service): 40 requests, 0 spans
- **LT-03** `ep:subscriber-service:GET:/api/subscribers/{}`: GET /api/subscribers/{id} (subscriber-service): 61 requests, 0 spans
- **LT-03** `ep:support-service:GET:/api/tickets/search`: GET /api/tickets/search (support-service): 39 requests, 0 spans
- **LT-03** `ep:support-service:GET:/api/tickets/{}`: GET /api/tickets/{id} (support-service): 38 requests, 0 spans
- **LT-03** `ep:usage-service:GET:/api/usage/{}`: GET /api/usage/{id} (usage-service): 52 requests, 0 spans
- **LT-03** `ep:usage-service:GET:/api/usage/{}/cdr`: GET /api/usage/{id}/cdr (usage-service): 44 requests, 0 spans
- **LT-03** `ep:subscriber-service:PATCH:/api/subscribers/{}`: PATCH /api/subscribers/{id} (subscriber-service): 42 requests, 0 spans
- **LT-03** `ep:auth-service:POST:/api/auth/session`: POST /api/auth/session (auth-service): 29 requests, 0 spans
- **LT-03** `ep:billing-service:POST:/api/bills/{}/pay`: POST /api/bills/{id}/pay (billing-service): 43 requests, 0 spans
- **LT-03** `ep:number-porting-service:POST:/api/porting`: POST /api/porting (number-porting-service): 35 requests, 0 spans
- **LT-03** `ep:sim-service:POST:/api/sims/{}/swap`: POST /api/sims/{id}/swap (sim-service): 41 requests, 0 spans
- **LT-03** `ep:support-service:POST:/api/tickets`: POST /api/tickets (support-service): 35 requests, 0 spans
