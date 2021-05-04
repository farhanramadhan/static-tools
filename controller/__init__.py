import analyzer
import transform
import visualize

def analyze_code(pythonfile):
    # transform to cfg
    cfg, g = transform.transformToCFG('./uploads/' + pythonfile)

    # analyze broken authentication
    vulnerabilities = analyzer.analyze(cfg, g, './uploads/' + pythonfile)

    # visualize output
    visualize.createImage(g, pythonfile)

    return vulnerabilities