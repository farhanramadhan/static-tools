def createImage(graph, pythonfile):
    ### Create Graph To output Directory
    graph.draw('static/'+ getFileName(pythonfile) + '.png', prog='dot')
    graph.close()

def getFileName(pythonfile):
    return pythonfile.split('/')[-1]