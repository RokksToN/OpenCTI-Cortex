#!/usr/bin/env python3
import requests
import json
from cortexutils.analyzer import Analyzer

class OpenCTIAnalyzer(Analyzer):
    """Searches for given Observables in configured OpenCTI instances. All standard data types are supported."""

    def __init__(self):
        Analyzer.__init__(self)

        self.service = self.get_param(
            'config.service', "search_exact", None)

        ssl = self.get_param('config.cert_check', True)
        names = self.get_param('config.name', None, 'No OpenCTI instance name given.')
        urls = self.get_param('config.url', None, 'No OpenCTI url given.')
        keys = self.get_param('config.key', None, 'No OpenCTI api key given.')
        proxies = self.get_param('config.proxy', None)        

        if len(names) != len(urls) or len(urls) != len(keys):
            self.error("Config error: please add a name, an url and a key for each OpenCTI instance.")

        else:
            try:
                self.openctis = []
                for i in range(len(names)):
                    self.openctis.append({
                        "name": names[i],
                        "url": urls[i],
                        "token": keys[i],
                        "ssl_verify": ssl,
                        "proxies": {'http': self.http_proxy, 'https': self.https_proxy}
                    })
            except Exception as e:
                self.error(str(e))

    def graphql_query(self, opencti, query):
        """Execute a GraphQL query against OpenCTI API"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {opencti['token']}"
        }
        url = opencti['url'].rstrip('/') + '/graphql'
        try:
            response = requests.post(
                url, 
                json={"query": query},
                headers=headers,
                verify=opencti['ssl_verify'],
                proxies=opencti['proxies'] if opencti['proxies'] else None,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            
            # Check for GraphQL errors
            if 'errors' in result:
                self.error(f"GraphQL Error: {result['errors']}")
            
            return result
        except Exception as e:
            self.error(f"Failed to query OpenCTI API: {str(e)}")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "OpenCTI"
        predicate = "Search Observable"

        found = 0
        for r in raw['results']:
            if r['observables']:
                found += len(r['observables'])

        value = ("Found " + str(found) + " observables") if found > 0 else "Not found"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):

        data = self.get_param('data', None, 'Data is missing')

        response = []

        for opencti in self.openctis:
            # Build GraphQL query for observables using search parameter
            observable_query = f"""
            {{
                stixCyberObservables(
                    search: "{data}",
                    first: 100
                ) {{
                    edges {{
                        node {{
                            id
                            observable_value
                            entity_type
                            created_at
                            updated_at
                        }}
                    }}
                }}
            }}
            """

            # Query observables
            result = self.graphql_query(opencti, observable_query)
            
            observables = []
            if 'data' in result and result['data']:
                edge_list = result['data'].get('stixCyberObservables', {}).get('edges', [])
                for edge in edge_list:
                    if edge.get('node'):
                        observable = edge['node']
                        
                        # Filter results to only keep exact matches if search_exact
                        if self.service == "search_exact" and observable.get("observable_value") != data:
                            continue
                        
                        # Add empty reports list for now
                        observable["reports"] = []
                        observables.append(observable)

            response.append({
                "name": opencti["name"],
                "url": opencti["url"],
                "observables": observables
            })

        self.report({'results': response})


if __name__ == '__main__':
    OpenCTIAnalyzer().run()
