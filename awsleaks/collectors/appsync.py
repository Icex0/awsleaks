import json
import os

from awsleaks.collectors.base import BaseCollector
from awsleaks import output as out


class AppSyncCollector(BaseCollector):
    service_name = "appsync"

    def collect(self):
        client = self.session.client("appsync")

        apis = client.list_graphql_apis().get("graphqlApis", [])
        for api in apis:
            api_id = api["apiId"]
            api_name = api.get("name", api_id)
            try:
                yield from self._collect_api(client, api_id, api_name)
            except Exception as e:
                out.error(f"AppSync {api_name}: {e}")

    def _collect_api(self, client, api_id, api_name):
        api_dir = os.path.join(self.output_dir, api_name)
        os.makedirs(api_dir, exist_ok=True)

        # Collect resolver templates
        types = client.list_types(apiId=api_id, format="SDL").get("types", [])
        for type_def in types:
            type_name = type_def["name"]
            try:
                resolvers = client.list_resolvers(
                    apiId=api_id, typeName=type_name
                ).get("resolvers", [])

                for resolver in resolvers:
                    field = resolver.get("fieldName", "unknown")
                    request_tpl = resolver.get("requestMappingTemplate", "")
                    response_tpl = resolver.get("responseMappingTemplate", "")

                    if request_tpl:
                        req_path = os.path.join(api_dir, f"{type_name}_{field}_request.vtl")
                        if not os.path.exists(req_path):
                            with open(req_path, "w") as f:
                                f.write(request_tpl)

                    if response_tpl:
                        resp_path = os.path.join(api_dir, f"{type_name}_{field}_response.vtl")
                        if not os.path.exists(resp_path):
                            with open(resp_path, "w") as f:
                                f.write(response_tpl)

            except Exception as e:
                out.error(f"AppSync {api_name}/{type_name}: {e}")

        out.status(f"Collected AppSync resolvers for {api_name}")
        yield (f"appsync_{api_name}", api_dir)
