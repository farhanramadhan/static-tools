#!/usr/bin/env python3
# Author: Rahul Gopinath <rahul.gopinath@cispa.saarland>
# License: GPLv3
"""
PyCFG for Python MCI
Use http://viz-js.com/ to view digraph output
"""

import ast
import re
import astunparse
import pygraphviz

class CFGNode(dict):
    registry = 0
    cache = {}
    stack = []
    def __init__(self, parents=[], ast=None):
        assert type(parents) is list
        self.parents = parents
        self.calls = []
        self.children = []
        self.ast_node = ast
        self.rid  = CFGNode.registry
        CFGNode.cache[self.rid] = self
        CFGNode.registry += 1

    def lineno(self):
        return self.ast_node.lineno if hasattr(self.ast_node, 'lineno') else 0

    def __str__(self):
        return "id:%d line[%d] parents: %s : %s" % (self.rid, self.lineno(), str([p.rid for p in self.parents]), self.source())

    def __repr__(self):
        return str(self)

    def add_child(self, c):
        if c not in self.children:
            self.children.append(c)

    def __eq__(self, other):
        return self.rid == other.rid

    def __neq__(self, other):
        return self.rid != other.rid

    def set_parents(self, p):
        self.parents = p

    def add_parent(self, p):
        if p not in self.parents:
            self.parents.append(p)

    def add_parents(self, ps):
        for p in ps:
            self.add_parent(p)

    def add_calls(self, func):
        self.calls.append(func)

    def source(self):
        return astunparse.unparse(self.ast_node).strip()

    def to_json(self):
        return {'id':self.rid, 'parents': [p.rid for p in self.parents], 'children': [c.rid for c in self.children], 'calls': self.calls, 'at':self.lineno() ,'ast':self.source()}

    @classmethod
    def to_graph(cls, arcs=[]):
        def unhack(v):
            for i in ['if', 'while', 'for', 'elif']:
                v = re.sub(r'^_%s:' % i, '%s:' % i, v)
            return v
        G = pygraphviz.AGraph(directed=True)
        cov_lines = set(i for i,j in arcs)
        # pylint: disable=unused-variable
        for nid, cnode in CFGNode.cache.items():
            G.add_node(cnode.rid)
            n = G.get_node(cnode.rid)
            lineno = cnode.lineno()
            # pylint: disable=no-member
            n.attr['label'] = "%d: %s" % (lineno, unhack(cnode.source()))
            for pn in cnode.parents:
                plineno = pn.lineno()
                if hasattr(pn, 'calllink') and pn.calllink > 0 and not hasattr(cnode, 'calleelink'):
                    G.add_edge(pn.rid, cnode.rid, style='dotted', weight=100)
                    continue

                if arcs:
                    if  (plineno, lineno) in arcs:
                        G.add_edge(pn.rid, cnode.rid, color='blue')
                    elif plineno == lineno and lineno in cov_lines:
                        G.add_edge(pn.rid, cnode.rid, color='blue')
                    elif hasattr(cnode, 'fn_exit_node') and plineno in cov_lines:  # child is exit and parent is covered
                        G.add_edge(pn.rid, cnode.rid, color='blue')
                    elif hasattr(pn, 'fn_exit_node') and len(set(n.lineno() for n in pn.parents) | cov_lines) > 0: # parent is exit and one of its parents is covered.
                        G.add_edge(pn.rid, cnode.rid, color='blue')
                    elif plineno in cov_lines and hasattr(cnode, 'calleelink'): # child is a callee (has calleelink) and one of the parents is covered.
                        G.add_edge(pn.rid, cnode.rid, color='blue')
                    else:
                        G.add_edge(pn.rid, cnode.rid, color='red')
                else:
                    G.add_edge(pn.rid, cnode.rid)
        return G

class PyCFG:
    """
    The python CFG
    """
    def __init__(self):
        self.founder = CFGNode(parents=[], ast=ast.parse('start').body[0]) # sentinel
        self.founder.ast_node.lineno = 0
        self.functions = {}
        self.functions_node = {}

    def parse(self, src):
        return ast.parse(src)

    def walk(self, node, myparents):
        if node is None: return
        fname = "on_%s" % node.__class__.__name__.lower()
        if hasattr(self, fname):
            fn = getattr(self, fname)
            v = fn(node, myparents)
            return v
        else:
            return myparents

    def on_module(self, node, myparents):
        """
        Module(stmt* body)
        """
        # each time a statement is executed unconditionally, make a link from
        # the result to next statement
        p = myparents
        for n in node.body:
            p = self.walk(n, p)
        return p

    def on_assign(self, node, myparents):
        """
        Assign(expr* targets, expr value)
        TODO: AugAssign(expr target, operator op, expr value)
        -- 'simple' indicates that we annotate simple name without parens
        TODO: AnnAssign(expr target, expr annotation, expr? value, int simple)
        """
        # pylint: disable=not-callable
        # pylint: disable=notimplemented-raised
        if len(node.targets) > 1: raise NotImplemented('Parallel assignments')

        p = [CFGNode(parents=myparents, ast=node)]
        p = self.walk(node.value, p)

        return p

    def on_pass(self, node, myparents):
        return [CFGNode(parents=myparents, ast=node)]

    def on_break(self, node, myparents):
        parent = myparents[0]
        while not hasattr(parent, 'exit_nodes'):
            # we have ordered parents
            parent = parent.parents[0]

        assert hasattr(parent, 'exit_nodes')
        p = CFGNode(parents=myparents, ast=node)

        # make the break one of the parents of label node.
        parent.exit_nodes.append(p)

        # break doesnt have immediate children
        return []

    def on_continue(self, node, myparents):
        parent = myparents[0]
        while not hasattr(parent, 'exit_nodes'):
            # we have ordered parents
            parent = parent.parents[0]
        assert hasattr(parent, 'exit_nodes')
        p = CFGNode(parents=myparents, ast=node)

        # make continue one of the parents of the original test node.
        parent.add_parent(p)

        # return the parent because a continue is not the parent
        # for the just next node
        return []

    def on_for(self, node, myparents):
        #node.target in node.iter: node.body
        _test_node = CFGNode(parents=myparents, ast=ast.parse('_for: True if %s else False' % astunparse.unparse(node.iter).strip()).body[0])
        ast.copy_location(_test_node.ast_node, node)

        # we attach the label node here so that break can find it.
        _test_node.exit_nodes = []
        test_node = self.walk(node.iter, [_test_node])

        extract_node = CFGNode(parents=[_test_node], ast=ast.parse('%s = %s.shift()' % (astunparse.unparse(node.target).strip(), astunparse.unparse(node.iter).strip())).body[0])
        ast.copy_location(extract_node.ast_node, _test_node.ast_node)

        # now we evaluate the body, one at a time.
        p1 = [extract_node]
        for n in node.body:
            p1 = self.walk(n, p1)

        # the test node is looped back at the end of processing.
        _test_node.add_parents(p1)

        return _test_node.exit_nodes + test_node


    def on_while(self, node, myparents):
        # For a while, the earliest parent is the node.test
        _test_node = CFGNode(parents=myparents, ast=ast.parse('_while: %s' % astunparse.unparse(node.test).strip()).body[0])
        ast.copy_location(_test_node.ast_node, node.test)
        _test_node.exit_nodes = []
        test_node = self.walk(node.test, [_test_node])

        # we attach the label node here so that break can find it.

        # now we evaluate the body, one at a time.
        p1 = test_node
        for n in node.body:
            p1 = self.walk(n, p1)

        # the test node is looped back at the end of processing.
        _test_node.add_parents(p1)

        # link label node back to the condition.
        return _test_node.exit_nodes + test_node

    def on_if(self, node, myparents):
        _test_node = CFGNode(parents=myparents, ast=ast.parse('_if: %s' % astunparse.unparse(node.test).strip()).body[0])
        ast.copy_location(_test_node.ast_node, node.test)
        test_node = self.walk(node.test, [_test_node])
        g1 = test_node
        for n in node.body:
            g1 = self.walk(n, g1)
        g2 = test_node
        for n in node.orelse:
            g2 = self.walk(n, g2)

        return g1 + g2

    def on_binop(self, node, myparents):
        left = self.walk(node.left, myparents)
        right = self.walk(node.right, left)
        return right

    def on_compare(self, node, myparents):
        left = self.walk(node.left, myparents)
        right = self.walk(node.comparators[0], left)
        return right

    def on_unaryop(self, node, myparents):
        return self.walk(node.operand, myparents)

    def on_call(self, node, myparents):
        def get_func(node):
            if type(node.func) is ast.Name:
                mid = node.func.id
            elif type(node.func) is ast.Attribute:
                mid = node.func.attr
            elif type(node.func) is ast.Call:
                mid = get_func(node.func)
            else:
                raise Exception(str(type(node.func)))
            return mid
                #mid = node.func.value.id

        p = myparents
        for a in node.args:
            p = self.walk(a, p)
        mid = get_func(node)
        myparents[0].add_calls(mid)

        # these need to be unlinked later if our module actually defines these
        # functions. Otherwsise we may leave them around.
        # during a call, the direct child is not the next
        # statement in text.
        for c in p:
            c.calllink = 0
        return p

    def on_expr(self, node, myparents):
        p = [CFGNode(parents=myparents, ast=node)]
        return self.walk(node.value, p)

    def on_return(self, node, myparents):
        parent = myparents[0]

        val_node = self.walk(node.value, myparents)
        # on return look back to the function definition.
        while not hasattr(parent, 'return_nodes'):
            parent = parent.parents[0]
        assert hasattr(parent, 'return_nodes')

        p = CFGNode(parents=val_node, ast=node)

        # make the break one of the parents of label node.
        parent.return_nodes.append(p)

        # return doesnt have immediate children
        return []

    def on_functiondef(self, node, myparents):
        # a function definition does not actually continue the thread of
        # control flow
        # name, args, body, decorator_list, returns
        fname = node.name
        # pylint: disable=unused-variable
        args = node.args
        # pylint: disable=unused-variable
        returns = node.returns

        enter_node = CFGNode(parents=[], ast=ast.parse('enter: %s(%s)' % (node.name, ', '.join([a.arg for a in node.args.args])) ).body[0]) # sentinel
        enter_node.calleelink = True
        ast.copy_location(enter_node.ast_node, node)
        exit_node = CFGNode(parents=[], ast=ast.parse('exit: %s(%s)' % (node.name, ', '.join([a.arg for a in node.args.args])) ).body[0]) # sentinel
        exit_node.fn_exit_node = True
        ast.copy_location(exit_node.ast_node, node)
        enter_node.return_nodes = [] # sentinel

        p = [enter_node]
        for n in node.body:
            p = self.walk(n, p)

        for n in p:
            if n not in enter_node.return_nodes:
                enter_node.return_nodes.append(n)

        for n in enter_node.return_nodes:
            exit_node.add_parent(n)

        self.functions[fname] = [enter_node, exit_node]
        self.functions_node[enter_node.lineno()] = fname

        return myparents

    def get_defining_function(self, node):
        if node.lineno() in self.functions_node: return self.functions_node[node.lineno()]
        if not node.parents:
            self.functions_node[node.lineno()] = ''
            return ''
        val = self.get_defining_function(node.parents[0])
        self.functions_node[node.lineno()] = val
        return val

    def link_functions(self):
        # pylint: disable=unused-variable
        for nid,node in CFGNode.cache.items():
            if node.calls:
                for calls in node.calls:
                    if calls in self.functions:
                        enter, exit = self.functions[calls]
                        enter.add_parent(node)
                        if node.children:
                            # # until we link the functions up, the node
                            # # should only have succeeding node in text as
                            # # children.
                            # assert(len(node.children) == 1)
                            # passn = node.children[0]
                            # # We require a single pass statement after every
                            # # call (which means no complex expressions)
                            # assert(type(passn.ast_node) == ast.Pass)

                            # # unlink the call statement
                            assert node.calllink > -1
                            node.calllink += 1
                            for i in node.children:
                                i.add_parent(exit)
                            # passn.set_parents([exit])
                            # ast.copy_location(exit.ast_node, passn.ast_node)


                            # #for c in passn.children: c.add_parent(exit)
                            # #passn.ast_node = exit.ast_node

    def update_functions(self):
        # pylint: disable=unused-variable
        for nid,node in CFGNode.cache.items():
            _n = self.get_defining_function(node)

    def update_children(self):
        # pylint: disable=unused-variable
        for nid,node in CFGNode.cache.items():
            for p in node.parents:
                p.add_child(node)

    def gen_cfg(self, src):
        """
        >>> i = PyCFG()
        >>> i.walk("100")
        5
        """
        node = self.parse(src)
        nodes = self.walk(node, [self.founder])
        self.last_node = CFGNode(parents=nodes, ast=ast.parse('stop').body[0])
        ast.copy_location(self.last_node.ast_node, self.founder.ast_node)
        self.update_children()
        self.update_functions()
        self.link_functions()

def compute_dominator(cfg, start = 0, key='parents'):
    dominator = {}
    dominator[start] = {start}
    all_nodes = set(cfg.keys())
    rem_nodes = all_nodes - {start}
    for n in rem_nodes:
        dominator[n] = all_nodes

    c = True
    while c:
        c = False
        for n in rem_nodes:
            pred_n = cfg[n][key]
            doms = [dominator[p] for p in pred_n]
            i = set.intersection(*doms) if doms else set()
            v = {n} | i
            if dominator[n] != v:
                c = True
            dominator[n] = v
    return dominator

def slurp(f):
    with open(f, 'r') as f: return f.read()


def get_cfg(pythonfile):
    cfg = PyCFG()
    cfg.gen_cfg(slurp(pythonfile).strip())
    cache = CFGNode.cache
    g = {}
    # pylint: disable=unused-variable
    for k,v in cache.items():
        j = v.to_json()
        at = j['at']
        parents_at = [cache[p].to_json()['at'] for p in j['parents']]
        children_at = [cache[c].to_json()['at'] for c in j['children']]
        if at not in g:
            g[at] = {'parents':set(), 'children':set()}
        # remove dummy nodes
        ps = set([p for p in parents_at if p != at])
        cs = set([c for c in children_at if c != at])
        g[at]['parents'] |= ps
        g[at]['children'] |= cs
        if v.calls:
            g[at]['calls'] = v.calls
        g[at]['function'] = cfg.functions_node[v.lineno()]
    return (g, cfg.founder.ast_node.lineno, cfg.last_node.ast_node.lineno)

def compute_flow(pythonfile):
    cfg,first,last = get_cfg(pythonfile)
    return cfg, compute_dominator(cfg, start=first), compute_dominator(cfg, start=last, key='children')


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
    # Knowledge
    checkSessionTimeout = ["permanent_session_lifetime", "PERMANENT_SESSION_LIFETIME"]
    for _, node in cfg.founder.cache.items():
        for sessionTimeoutStatement in checkSessionTimeout:
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
    checkCreateSession = [('session[', ']')]
    for _, node in cfg.founder.cache.items():
        leftSideVariable = node.source().partition("=")[0]
        for createSessionStatement in checkCreateSession:
            if leftSideVariable.find(createSessionStatement[0]) != -1 and leftSideVariable.find(createSessionStatement[1]) != -1:
                sessionCreatedNode.append(node)
    return

def addDeleteSessionNode(cfg, sessionDestroyedNode):
    checkDestroySession = ['session.pop', 'session.clear']
    for _, node in cfg.founder.cache.items():
        for destroySessionStatement in checkDestroySession:
            if node.source().find(destroySessionStatement) != -1:
                sessionDestroyedNode.append(node)
    return

def checkSessionLifetime(cfg, sessionCreatedNode, sessionDestroyedNode):
    parameter_exp = ['\'', '\"']
    createdSession = {}
    deletedSession = {}
    vulnerableSessionLifetime = []
    sessionSecureLifetime = []

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
        # print(sessionSecure)
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
def isPasswordHashed(cfg, passwordInputNodes):
    hashKeywords = ['hashlib', 'encrypt', 'hash', 'encode']
    passwordHashedNode = []
    passwordNotHashedNode = []
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
                for hashKeyword in hashKeywords:
                    if cfg.founder.cache.get(rid).source().find(hashKeyword) != -1:
                        passwordHashed = True
                        # check if password variable change name
                        if cfg.founder.cache.get(rid).source().find('=') != -1:
                            passwordVariable = cfg.founder.cache.get(rid).source().partition('=')[0]
                            if passwordVariable.find(' ') != -1:
                                passwordVariable = passwordVariable.partition(' ')[0]
                ## Access Curent Node
                rid = rid + 1
        
        # if password hashed and the hashed password executed in mysql statement
        if passwordHashedExecuted and passwordHashed:
            passwordHashedNode.append(passwordInputNode)
        else:
            passwordNotHashedNode.append(passwordInputNode)
    
    return passwordHashedNode, passwordNotHashedNode

def isNodeHaveSQLStatementAndPassword(cfgnode, passwordHashed, passwordHashedExecuted):
    sqlStatements = ['SELECT', 'select', 'Select', 'UPDATE', 'update', 'Update', 'INSERT', 'insert', 'Insert', 'DELETE', 'Delete', 'delete']
    for sqlStatement in sqlStatements:
        if cfgnode.source().find(sqlStatement) != -1 and cfgnode.source().find(passwordHashed) != -1:
            return (True, True)
        # end of function return (finish, sql statement executed or not with password hashed)
        if cfgnode.source().find('enter:') != -1:
            return (True, False)
    return (False, False)

def getPasswordInputNodeFromUser(cfg):
    passwordInputNodes = {}
    passwordKeywords = ['password', 'pass', 'pwd']
    userInputs = ['request']
    for _, node in cfg.founder.cache.items():
        for passwordKeyword in passwordKeywords:
            for userInput in userInputs:
                if node.source().find(passwordKeyword) != -1 and node.source().find(userInput) != -1:
                    passwordInputNodes[node.rid] = node
    return passwordInputNodes

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

if __name__ == '__main__':
    import json
    import sys
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('pythonfile', help='The python file to be analyzed')
    parser.add_argument('-d','--dots', action='store_true', help='generate a dot file')
    parser.add_argument('-c','--cfg', action='store_true', help='print cfg')
    parser.add_argument('-x','--coverage', action='store', dest='coverage', type=str, help='branch coverage file')
    parser.add_argument('-y','--ccoverage', action='store', dest='ccoverage', type=str, help='custom coverage file')
    args = parser.parse_args()
    # print("args " , args)
    if args.dots:
        arcs = None
        if args.coverage:
            # pylint: disable=undefined-variable
            cdata = coverage.CoverageData()
            cdata.read_file(filename=args.coverage)
            arcs = [(abs(i),abs(j)) for i,j in cdata.arcs(cdata.measured_files()[0])]
        elif args.ccoverage:
            arcs = [(i,j) for i,j in json.loads(open(args.ccoverage).read())]
        else:
            arcs = []
        cfg = PyCFG()
        cfg.gen_cfg(slurp(args.pythonfile).strip())
        g = CFGNode.to_graph(arcs)

        # print(get_cfg(args.pythonfile))

        # <- Broken Authentication Finder ->
        # Parameter To Detect Broken Authentication Vulnerable
        sessionTimeout = False
        sessionCreatedNode = [] # Can be boolean value or list
        sessionDestroyedNode = [] # Can be boolean value or list
        passwordHashed = [] # Can be boolean value or list
        passwordNotHashed = [] # Can be boolean value or list
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
        passwordInputNodes = getPasswordInputNodeFromUser(cfg)
        passwordHashed, passwordNotHashed = isPasswordHashed(cfg, passwordInputNodes)

        ### Change Color For Each Node That Vulnerable and Append to listOfVulnerable
        drawGraphForSessionTimeout(sessionTimeout, g, cfg, listOfVulnerable)
        drawGraphForSessionLifetime(vulnerableSessionLifetime, sessionSecureLifetime, g, cfg, listOfVulnerable)
        drawGraphForPasswordHash(passwordHashed, passwordNotHashed, g, cfg, listOfVulnerable)

        ### Print to Terminal Vulnerable Lines
        printToTerminal(listOfVulnerable)

        ### Create Graph To output Directory
        g.draw('output/'+args.pythonfile + '.png', prog='dot')
        ### print to cfg terminal (default)
        # print(g.string(), file=sys.stderr)
        # for _, node in cfg.founder.cache.items():
        #     print(node.rid,node,node.ast_node.__dict__)

        # cfg.parse()
    elif args.cfg:
        cfg,first,last = get_cfg(args.pythonfile)
        for i in sorted(cfg.keys()):
            print(i,'parents:', cfg[i]['parents'], 'children:', cfg[i]['children'])
