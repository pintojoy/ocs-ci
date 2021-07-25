# -*- coding: utf8 -*-
"""
Test the collection of Cadviser metrics.
"""
import logging
from ocs_ci.framework.testlib import scale, E2ETest
from ocs_ci.ocs.metrics import collect_pod_metrics


@scale
class TestScaleMetrics(E2ETest):
    """
    Skeleton test that for now just displays metrics extracted from
    the collect_cadvisor_metrics library routine
    """

    def test_scale_metrics(self):
        logging.info("starting test_scale_metrics")
        metrics = collect_pod_metrics()
        logging.info(metrics)
