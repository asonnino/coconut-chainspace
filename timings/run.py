""" Simple benchmark function to measure contract's execution time. """

###############################################################
# imports
###############################################################
import time
import numpy


###############################################################
# tester -- benchmarking framework
###############################################################
def run(repeat, test_name, test_to_run, *args):
    # repeat the experiemnt 'repeat' times 
    times = []
    for i in range(repeat):
        # take average over 'repeat' execution (timer resolution)
        start_time = time.time()
        for i in range(repeat):
            # DUT
            test_to_run(*args)

        end_time = time.time()
        times.append( (end_time-start_time)/ repeat * 1000)

    # compute mean and std
    mean = numpy.mean(times)
    sd = numpy.std(times)

    # print result
    print "tx " +test_name+ "\t\t{:.10f}\t\t{:.10f}\t\t{}".format(mean, sd, repeat)


def run_checker(repeat, test_name, test_to_run, solution):
    # repeat the experiemnt 'repeat' times 
    times = []
    for i in range(repeat):
        # take average over 'repeat' execution (timer resolution)
        start_time = time.time()
        for i in range(repeat):
            # DUT
            test_to_run(
                solution['inputs'],
                solution['referenceInputs'],
                solution['parameters'],
                solution['outputs'],
                solution['returns'],
                solution['dependencies']
            )

        end_time = time.time()
        times.append( (end_time-start_time)/ repeat * 1000)

    # compute mean and std
    mean = numpy.mean(times)
    sd = numpy.std(times)

    # print result
    print "tx " +test_name+ "\t\t{:.10f}\t\t{:.10f}\t\t{}".format(mean, sd, repeat)

###############################################################


