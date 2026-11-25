import logging
from neo4j import GraphDatabase
from app.config import settings
from app.graph.graph_builder import check_neo4j_online
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class GraphQueries:
    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = settings.NEO4J_PASSWORD
        self.driver = None

    def __enter__(self):
        if not check_neo4j_online(self.uri):
            self.driver = None
            return self

        try:
            auth = (self.user, self.password) if self.password else None
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=auth,
                connection_timeout=0.2,
                max_connection_lifetime=5,
            )
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j driver at {self.uri}: {e}")
            self.driver = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.driver:
            try:
                self.driver.close()
            except Exception:
                pass

    def get_campaign_subgraph(self, event_ids: List[str]) -> Dict[str, Any]:
        """
        Retrieves nodes and edges representing the subgraph around a list of event IDs,
        formatted for frontend graph libraries (e.g. react-force-graph, cytoscape).
        """
        if not self.driver:
            logger.warning("Neo4j driver not connected. Returning empty subgraph.")
            return {"nodes": [], "edges": []}

        # Cypher query to retrieve paths up to 2 hops from the campaign events
        query = """
        MATCH (e:Event) WHERE e.event_id IN $event_ids
        OPTIONAL MATCH path = (e)-[r*1..2]-(n)
        RETURN path, e
        """
        
        nodes_dict: Dict[str, Any] = {}
        edges_set = set()

        try:
            with self.driver.session() as session:
                result = session.run(query, event_ids=event_ids)
                for record in result:
                    # Always include the core Event nodes, even if they have no relationships
                    core_event = record["e"]
                    if core_event:
                        eid = core_event.element_id
                        nodes_dict[eid] = {
                            "id": eid,
                            "type": "Event",
                            "name": core_event.get("event_type", "Event"),
                            "properties": dict(core_event.items())
                        }

                    path = record["path"]
                    if not path:
                        continue
                    
                    for node in path.nodes:
                        nid = node.element_id
                        labels = list(node.labels)
                        primary_label = labels[0] if labels else "Entity"
                        
                        # Determine human-friendly name
                        name = (
                            node.get("name") or 
                            node.get("address") or 
                            node.get("hash") or 
                            node.get("event_type") or 
                            node.get("event_id") or 
                            nid
                        )
                        
                        nodes_dict[nid] = {
                            "id": nid,
                            "type": primary_label,
                            "name": name,
                            "properties": dict(node.items())
                        }
                    
                    for rel in path.relationships:
                        edges_set.add((
                            rel.start_node.element_id,
                            rel.end_node.element_id,
                            rel.type
                        ))
        except Exception as e:
            logger.error(f"Error querying campaign subgraph: {e}")
            return {"nodes": [], "edges": []}

        return {
            "nodes": list(nodes_dict.values()),
            "edges": [{"source": s, "target": t, "type": ty} for s, t, ty in edges_set]
        }
