import analyzer
import transform
import visualize
import time

def analyze_code(pythonfile):
    # transform to cfg
    cfg, g = transform.transformToCFG('./uploads/' + pythonfile)

    start_time = time.time()
    # analyze broken authentication
    vulnerabilities, count_node = analyzer.analyze(cfg, g, './uploads/' + pythonfile)
    end_time = time.time()

    # analyze time in second
    exec_time = end_time - start_time

    # visualize output
    visualize.createImage(g, pythonfile)

    return vulnerabilities, exec_time*1000, count_node