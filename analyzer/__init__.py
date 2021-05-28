import transform
from dictionary import password, session_create, session_delete, session_timeout, sql

## Function To Check Vulnerable
def getAppNodeRid(cfg):
    checkApp = ["app ="]
    for _, node in cfg.founder.cache.items():
        for appString in checkApp:
            if node.source().find(appString) != -1:
                return node.rid

class Vulnerable:
    def __init__(self, node, vulnerable_type):
        # cfgNode
        self.node = node
        # string for cmd print
        self.vulnerable_type = vulnerable_type

### Session Timeout
def isSessionHaveTimeout(cfg):
    for _, node in cfg.founder.cache.items():
        for sessionTimeoutStatement in session_timeout.sessionTimeoutKeyword:
            if node.source().find(sessionTimeoutStatement) != -1:
                return node.rid, True
    return -1, False

def drawGraphForSessionTimeout(sessionTimeout, aGraph, cfg, listOfVulnerable):
    # Check Set Session Timeout Or Not
    if sessionTimeout[1]: # eg. sessionTimeout = (-1, False)
        node = aGraph.get_node(sessionTimeout[0])
        # pylint: disable=no-member
        node.attr['color'] = 'green'
    else: # If Session Timeout Not Set give color red to App Node
        appNodeRid = getAppNodeRid(cfg)
        if (appNodeRid is None):
            return
        #AGraph node
        node = aGraph.get_node(appNodeRid)
        node.attr['color'] = 'red'
        #cfg node
        cfgNode = cfg.founder.cache.get(appNodeRid)
        vulnerable = Vulnerable(cfgNode, 'Session Timeout Not Set')
        listOfVulnerable.append(vulnerable)

### Session Lifetime
def addCreateSessionNode(cfg, sessionCreatedNode):
    for _, node in cfg.founder.cache.items():
        leftSideVariable = node.source().partition("=")[0]
        for createSessionStatement in session_create.session_create:
            if leftSideVariable.find(createSessionStatement[0]) != -1 and leftSideVariable.find(createSessionStatement[1]) != -1:
                sessionCreatedNode.append(node)
    return

def addDeleteSessionNode(cfg, sessionDestroyedNode):
    for _, node in cfg.founder.cache.items():
        for destroySessionStatement in session_delete.session_delete:
            if node.source().find(destroySessionStatement) != -1:
                sessionDestroyedNode.append(node)
    return

def isClearSessionNodeExist(cfg):
    for _, node in cfg.founder.cache.items():
        for clearSessionStatement in session_delete.session_clear:
            if node.source().find(clearSessionStatement) != -1:
                return True
    return False

def checkSessionLifetime(cfg, sessionCreatedNode, sessionDestroyedNode):
    parameter_exp = ['\'', '\"']
    createdSession = {}
    deletedSession = {}
    vulnerableSessionLifetime = []
    sessionSecureLifetime = []

    if not isClearSessionNodeExist(cfg):
        # get session created
        for node in sessionCreatedNode:
            for exp in parameter_exp:
                front = (node.source().find(exp))
                back = (node.source().find(exp, front+1))
                if front > -1:
                    createdSession[node.source()[front+1:back]] = node
        
        # get session delete
        for node in sessionDestroyedNode:
            for exp in parameter_exp:
                front = (node.source().find(exp))
                back = (node.source().find(exp, front+1))
                if front > -1:
                    deletedSession[(node.source()[front+1:back])] = node

        # check per session whether the session destroyed or not
        for key in createdSession.keys():
            if deletedSession.get(key) is None:
                vulnerableSessionLifetime.append(createdSession.get(key))
            else:
                sessionSecureLifetime.append(createdSession.get(key))
                sessionSecureLifetime.append(deletedSession.get(key))

    return vulnerableSessionLifetime, sessionSecureLifetime

def drawGraphForSessionLifetime(vulnerableSessionLifetime, sessionSecureLifetime, aGraph, cfg, listOfVulnerable):
    # Check Session Secure
    for sessionSecure in sessionSecureLifetime:
        node = aGraph.get_node(sessionSecure.rid)
        # pylint: disable=no-member
        node.attr['color'] = 'green'

    # If Session Timeout Not Set give color red to App Node
    for vulnerableLifetime in vulnerableSessionLifetime:
        #AGraph node
        node = aGraph.get_node(vulnerableLifetime.rid)
        node.attr['color'] = 'red'
        #cfg node
        vulnerable = Vulnerable(vulnerableLifetime, 'Session Not Destroyed')
        listOfVulnerable.append(vulnerable)

### Password Hash
def isPasswordHashed(cfg, passwordInputNodes, passwordHashedNode, passwordNotHashedNode):
    # start from input user that contain password
    for passwordInputNode in passwordInputNodes.values():
        passwordHashed = False
        passwordHashedExecuted = False

        # sanitize password variable
        passwordVariable = passwordInputNode.source().partition('=')[0]
        if passwordVariable.find(' ') != -1:
            passwordVariable = passwordVariable.partition(' ')[0]

        # check password from input to execute sql statement that contains hashed password or to end of function
        if not passwordHashed:
            rid = passwordInputNode.rid
            isNodeSQLStatementAndPassword = False
            while not isNodeSQLStatementAndPassword:
                isNodeSQLStatementAndPassword, passwordHashedExecuted = isNodeHaveSQLStatementAndPassword(cfg.founder.cache.get(rid), passwordVariable, passwordHashedExecuted)
                for hashKeyword in password.password_hashed:
                    if cfg.founder.cache.get(rid).source().find(hashKeyword) != -1:
                        passwordHashed = True
                        # check if password variable change name
                        if cfg.founder.cache.get(rid).source().find('=') != -1:
                            passwordVariable = cfg.founder.cache.get(rid).source().partition('=')[0]
                            if passwordVariable.find(' ') != -1:
                                passwordVariable = passwordVariable.partition(' ')[0]
                ## Access Curent Node
                rid = rid + 1
                if cfg.founder.cache.get(rid) is None:
                    break
        
        # if password hashed and the hashed password executed in mysql statement
        if passwordHashedExecuted and passwordHashed:
            passwordHashedNode.append(passwordInputNode)
        else:
            passwordNotHashedNode.append(passwordInputNode)
    
    return

def isNodeHaveSQLStatementAndPassword(cfgnode, passwordHashed, passwordHashedExecuted):
    for sqlStatement in sql.sql_statement:
        if cfgnode.source().find(sqlStatement) != -1 and cfgnode.source().find(passwordHashed) != -1:
            return (True, True)
        # end of function return (finish, sql statement executed or not with password hashed)
        if cfgnode.source().find('enter:') != -1:
            return (True, False)
    return (False, False)

def getPasswordInputNodeFromUser(cfg, passwordInputNodes):
    for _, node in cfg.founder.cache.items():
        for passwordKeyword in password.password_keyword_input:
            for userInput in password.user_input:
                if node.source().find(passwordKeyword) != -1 and node.source().find(userInput) != -1:
                    passwordInputNodes[node.rid] = node
    return

def drawGraphForPasswordHash(passwordHashed, passwordNotHashed, aGraph, cfg, listOfVulnerable):
    # Check password hashed
    for passwordHash in passwordHashed:
        node = aGraph.get_node(passwordHash.rid)
        # pylint: disable=no-member
        node.attr['color'] = 'green'

    # If Password Not Hashed Set give color red to App Node
    for passwordNotHash in passwordNotHashed:
        #AGraph node
        node = aGraph.get_node(passwordNotHash.rid)
        node.attr['color'] = 'red'
        #cfg node
        vulnerable = Vulnerable(passwordNotHash, 'Password Not Hashed')
        listOfVulnerable.append(vulnerable)

def printToTerminal(listOfVulnerable):
    print("List Vulnerable : ")
    if len(listOfVulnerable) < 1:
        print('No Vulnerable Found')
    else:
        for vulnerable in listOfVulnerable:
            print('[' + vulnerable.vulnerable_type + '] = ' + str(vulnerable.node))

def analyze(cfg, g, pythonfile):        

    # print(cfg.founder.cache)
    # # return

    # # get_cfg(pythonfile)

    # <- Broken Authentication Finder ->
    # Parameter To Detect Broken Authentication Vulnerable
    sessionTimeout = False
    sessionCreatedNode = [] # Can be boolean value or list
    sessionDestroyedNode = [] # Can be boolean value or list
    passwordHashedNode = [] # Can be boolean value or list
    passwordNotHashedNode = [] # Can be boolean value or list
    passwordInputNodes = {}
    vulnerableSessionLifetime = []
    sessionSecureLifetime = []
    listOfVulnerable = []

    ### - Check Session Timeout Exist Or Not eg. (app.permanent_session_lifetime = ...)
    sessionTimeout = isSessionHaveTimeout(cfg)

    ### - Check Session Lifetime
    ####   -> Check Create Session eg. session['username'] = ...
    addCreateSessionNode(cfg, sessionCreatedNode)
    ####   -> Check Session Terminated Or Not eg. session.pop('username', None)
    addDeleteSessionNode(cfg, sessionDestroyedNode)
    ####   -> Check Session Lifetime
    vulnerableSessionLifetime, sessionSecureLifetime = checkSessionLifetime(cfg, sessionCreatedNode, sessionDestroyedNode)

    ### - Check Password Hash Or Not when Register eg. INSERT ..., hashlib.md5
    getPasswordInputNodeFromUser(cfg, passwordInputNodes)
    isPasswordHashed(cfg, passwordInputNodes, passwordHashedNode, passwordNotHashedNode)

    ### Change Color For Each Node That Vulnerable and Append to listOfVulnerable
    drawGraphForSessionTimeout(sessionTimeout, g, cfg, listOfVulnerable)
    drawGraphForSessionLifetime(vulnerableSessionLifetime, sessionSecureLifetime, g, cfg, listOfVulnerable)
    drawGraphForPasswordHash(passwordHashedNode, passwordNotHashedNode, g, cfg, listOfVulnerable)

    ### Print to Terminal Vulnerable Lines
    printToTerminal(listOfVulnerable)

    count_node = len(cfg.founder.cache.items())
    print(transform.CFGNode.cache)
    
    # reset CFG Node Static Variable
    transform.CFGNode.registry = 0
    transform.CFGNode.cache = {}
    transform.CFGNode.stack = []

    return listOfVulnerable, count_node
