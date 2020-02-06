# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

try:
    from neo4j.v1 import GraphDatabase
except ImportError:
    from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable

from sprayhound.utils.defines import *


class Neo4jConnection:
    class Options:
        def __init__(self, host, user, password, port, log, edge_blacklist=None):
            self.user = user
            self.password = password
            self.host = host
            self.port = port
            self.log = log
            self.edge_blacklist = edge_blacklist if edge_blacklist is not None else []

    def __init__(self, options):
        self.user = options.user
        self.password = options.password
        self.log = options.log
        self.edge_blacklist = options.edge_blacklist
        self._uri = "bolt://{}:{}".format(options.host, options.port)
        self._driver = None

    def set_as_owned(self, username, domain):
        ret = self._get_driver()
        if not ret.success():
            return ret
        user = self._format_username(username, domain)
        query = "MATCH (u:User {{name:\"{}\"}}) SET u.owned=True RETURN u.name AS name".format(user)
        result = self._run_query(query)
        if len(result.value()) > 0:
            return RetCode(ERROR_SUCCESS)
        else:
            return RetCode(ERROR_NEO4J_NON_EXISTENT_NODE, "Node {} does not exist".format(user))

    def bloodhound_analysis(self, username, domain):
        ret = self._get_driver()
        if not ret.success():
            return ret

        edges = [
            "MemberOf",
            "HasSession",
            "AdminTo",
            "AllExtendedRights",
            "AddMember",
            "ForceChangePassword",
            "GenericAll",
            "GenericWrite",
            "Owns",
            "WriteDacl",
            "WriteOwner",
            "CanRDP",
            "ExecuteDCOM",
            "AllowedToDelegate",
            "ReadLAPSPassword",
            "Contains",
            "GpLink",
            "AddAllowedToAct",
            "AllowedToAct",
            "SQLAdmin"
        ]
        # Remove blacklisted edges
        without_edges = [e.lower() for e in self.edge_blacklist]
        effective_edges = [edge for edge in edges if edge.lower() not in without_edges]

        user = self._format_username(username, domain)

        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                query = """
                    MATCH (n:User {{name:\"{}\"}}),(m:Group),p=shortestPath((n)-[r:{}*1..]->(m))
                    WHERE m.objectsid ENDS WITH "-512" 
                    RETURN COUNT(p) AS pathNb
                    """.format(user, '|'.join(effective_edges))

                self.log.debug("Query : {}".format(query))
                result = tx.run(query)
        return RetCode(ERROR_SUCCESS) if result.value()[0] > 0 else RetCode(ERROR_NO_PATH)

    def clean(self):
        if self._driver is not None:
            self._driver.close()
        return RetCode(ERROR_SUCCESS)

    def _run_query(self, query):
        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                return tx.run(query)

    def _get_driver(self):
        if self._driver is not None:
            return RetCode(ERROR_SUCCESS)

        try:
            self._driver = GraphDatabase.driver(self._uri, auth=(self.user, self.password))
            return RetCode(ERROR_SUCCESS)
        except AuthError as e:
            return RetCode(ERROR_NEO4J_CREDENTIALS, e)
        except ServiceUnavailable as e:
            return RetCode(ERROR_NEO4J_SERVICE_UNAVAILABLE, e)
        except Exception as e:
            return RetCode(ERROR_NEO4J_UNEXPECTED, e)

    @staticmethod
    def _format_username(user, domain):
        return (user + "@" + domain).upper()