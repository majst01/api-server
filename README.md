# metal-stack api server

This is meant as a POC implementation of the main api-server used to provide a MVP of our metal-stack offering.

The API server is

responsible for:

- expose all required API calls to the web frontend and the cli
- define our business objects and relations
- authenticate and authorize these calls
- know which real backends, like github, gardener, metal-stack and others must be called to execute the business logic

not responsible for:

- serve the web frontend code fragments, this should be done by a https server in front of, or beside the api-server

The API Server should be stateless if possible, all state must be persisted in one of the backends.

All API Endpoints are currently exposed as REST and GRPC.

## Development

To build this server some requirements need to be met on the developers workstation.

- go >= v1.21.x, see [https://go.dev/dl/](https://go.dev/dl/)
- make
- golanci-lint, download from [https://github.com/golangci/golangci-lint/releases](https://github.com/golangci/golangci-lint/releases)
- [httpYac](https://marketplace.visualstudio.com/items?itemName=anweber.vscode-httpyac) extension to your vscode for much easier local endpoint testing
- [grpcurl](https://github.com/fullstorydev/grpcurl) to make manual grpc calls
- [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#running-opa) to run opa tests

Install Open Policy Agent (opa) on your machine:

```bash
curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/[LATEST_VERSION]/opa_linux_amd64_static
chmod 755 /usr/local/bin/opa
```

Simply running `make` generates the binary of the api-server as `bin/server`.

It is required to have the backing store `masterdata-api` up and running, this can be done by executing:

```bash
make masterdata-up
```

The server can be started by executing `bin/server serve` or `make run serve` and you should see the following output:

```bash
{"level":"info","ts":"2022-02-25T08:17:55.915+0100","caller":"server/main.go:41","msg":"running api-server","version":"devel (db0109ae), heads/main-0-gdb0109a, 2022-02-23T21:10:47+01:00, go1.17.5","level":"info","grpc endpoint":"localhost:9090","http endpoint":"localhost:8080"}
{"level":"info","ts":"2022-02-25T08:17:55.948+0100","caller":"server/server.go:85","msg":"Listening for GRPC on localhost:9090"}
{"level":"info","ts":"2022-02-25T08:17:55.953+0100","caller":"server/server.go:153","msg":"Serving gRPC-Gateway on localhost:8080"}
```

In the `test` folder are preconfigured `restclient` files which can be executed in vscode. They will then call the API endpoint running locally on your machine.

### Set Env for Authentication

```bash
# needed for GitHub auth
export SESSION_SECRET=<your secret (random string)>
export GH_CLIENT_SECRET=<client secret of GitHub OAuth App>
export GH_CLIENT_ID=<client ID of GitHub OAuth App>
# needed for stripe usage
export STRIPE_SECRET_KEY=<stripe secret>
# set to dev if you do not want to use gardener and metal-api clients
export STAGE=DEV
```

### Setup Stripe

You need to add the stripe secret key to your env as shown above.

To create our current product and price objects in stripe run:

```bash
./bin/server --log-level debug setup-stripe
```

If your stripe account already has some objects you may want to delete them. If they were already used this is complicated to do. A good way to circumvent this is problem is to delete all test data and start fresh. You can do this in the dashboard developer view. At the bottom of the page is a button to delete all test data.

### Directory structure

Domain model and api endpoints are defined and implemented in the [api](https://github.com/metal-stack/api).

The service implementation for every defined service is located in:

- `pkg/service/[name of the domain]`

As an example the `cluster` service is located in `pkg/service/cluster/cluster-service.go`.

### Manual service access

It is possible to call the exposed services in two ways:

- The grpc endpoint with `grpcurl`

List exposed services:

```bash
$ grpcurl -plaintext localhost:8080 list
admin.v1.ClusterService
admin.v1.PaymentService
admin.v1.StorageService
admin.v1.TenantService
admin.v1.TokenService
api.v1.AssetService
api.v1.ClusterService
api.v1.HealthService
api.v1.IPService
api.v1.MethodService
api.v1.PaymentService
api.v1.SnapshotService
api.v1.TenantService
api.v1.TokenService
api.v1.VersionService
api.v1.VolumeService
status.v1.MessageService
status.v1.StatusService
```

Call a service without arguments

```bash
$ grpcurl -plaintext localhost:8080 api.v1.VersionService/Get
{
  "version": {
    "version": "devel",
    "revision": "heads/main-0-ga39b49d",
    "gitSha1": "a39b49d7",
    "buildDate": "2022-03-18T08:32:35+01:00"
  }
}
```

Can also be done with `buf` with different protocols

```bash
buf curl -v --http2-prior-knowledge --protocol grpc    http://localhost:8080/api.v1.VersionService/Get
buf curl -v --http2-prior-knowledge --protocol grpcweb http://localhost:8080/api.v1.VersionService/Get
buf curl -v --http2-prior-knowledge --protocol connect http://localhost:8080/api.v1.VersionService/Get
{
  "version": {
    "version": "fix-server-reflection",
    "revision": "heads/fix-server-reflection-0-g09835e2",
    "gitSha1": "09835e2d",
    "buildDate": "2023-12-18T12:04:12+01:00"
  }
}
```

Or even with `curl`

```bash
curl -v -X POST -d '{}' -H 'Content-Type: application/json' https://api.metalstack.cloud:443/api.v1.VersionService/Get
```

More complex example with jwt header and payload

```bash
$ grpcurl \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJtZXRhbC1zdGFjay1jbG91ZCIsImV4cCI6MTY1MDA1NTQyMiwibmJmIjoxNjQ3NDYzNDIyLCJpYXQiOjE2NDc0NjM0MjIsImp0aSI6ImQxNDAyNjJhLTdkMzgtNDE0OC04OTRmLTdjOTI1MGNhYmI1NiIsInBlcm1pc3Npb25zIjp7InByb2plY3QtYSI6WyIvYXBpLnYxLkFzc2V0U2VydmljZS9HZXQiLCIvYXBpLnYxLkFzc2V0U2VydmljZS9MaXN0UmVnaW9ucyIsIi9hcGkudjEuQ2x1c3RlclNlcnZpY2UvQ3JlYXRlIiwiL2FwaS52MS5DbHVzdGVyU2VydmljZS9HZXQiLCIvYXBpLnYxLkNsdXN0ZXJTZXJ2aWNlL0xpc3QiLCIvYXBpLnYxLkNsdXN0ZXJTZXJ2aWNlL0RlbGV0ZSIsIi9hcGkudjEuQ2x1c3RlclNlcnZpY2UvVXBkYXRlIl19fQ.W1oPpaRcbGUs8X3TldKdPUzXR8oHRXwN5YDIzAum2Qk" \
  -plaintext \
  -d '{ "project":"project-a" }' localhost:8080 api.v1.ClusterService/List
```

## Authorization an Authentication

The idea is to rely on jwt token [jwt.io](jwt.io) based authentication and authorization. The validation and extraction of the jwt token, as well as the decision making based on the content of the jwt token payload and the service endpoint called is delegated to a framework called [OPA](openpolicyagent.org).

For further details see [docs](docs/roles.md)

## Auditing

To audit all events on the api-server, all api calls are sent to a search index if configured. [Meilisearch](https://www.meilisearch.com/) is used as a modern index database. Meilisearch can be started locally by executing:

```bash
make auditing-up
```

after that, starting the api-server can be started with auditing enabled, default is disabled:

```bash
bin/server serve --auditing-enabled=true
```

Log in in the console app and open your browser at [http://localhost:7700](http://localhost:7700), enter `geheim` in the API Key prompt and start to see what happened.

![Audit search](docs/auditing.png)

Enjoy.

## Validation

Request validation is done already in the proto message level and enforced by a grpc interceptor.
Every field/property of a request message can be annotated with `proto` options comming from the [protoc-gen-validate](https://github.com/envoyproxy/protoc-gen-validate) project.

As an example see this IPGetRequest message:

```proto
message IPServiceGetRequest {
  string uuid = 1 [(validate.rules).string.uuid = true];
  string project = 2 [(validate.rules).string = {
    min_len: 2,
    max_len: 128
  }];
}
```

Here the `uuid` field must be parsable to a UUID and project must be a string with a minimum of 2 characters and a maximum of 128 characters.
During `proto` compilation, for every message a `.Validate()` method is generated and the Interceptor will call this method and return an error if validation does not pass.

For new messages please add at least the minimum validation rules to free the business logic validation from repeated simple validation.
All available validation rules can be seen here: [Constraint-rules](https://github.com/envoyproxy/protoc-gen-validate#constraint-rules).

## Local Certs

The certs in [certs/](certs/) are only used in the local setup.  
They will expire on the 31.03.2024.  
To regenrate them you can run these commands:

```bash
cd certs
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server server.json | cfssljson -bare server
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client client.json | cfssljson -bare client
```
