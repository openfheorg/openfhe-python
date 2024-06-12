"""
This is a specially-named file that pytest finds in order to
configure testing. Most of the logic comes from
https://docs.pytest.org/en/7.1.x/example/simple.html#control-skipping-of-tests-according-to-command-line-option
"""
import pytest


class CustomMarker:
    """
    Custom Markers are used to annotate tests.

    Tests marked with a custom marker will be skipped by default. Pass either

        --run-NAME_OF_MARKER or --run-NAME-OF-MARKER

    to override this behavior.

    --run-all may also be used to run all marked tests.
    """
    def __init__(self, name, desc, dest=None):
        self.name = name
        self.desc = desc
        self.dest = name if dest is None else dest

    def option_flags(self):
        """
        Return option flags for this marker.

        >>> marker = CustomMarker('foo_bar', 'my desc')
        >>> marker.option_flags()
        ['--run-foo_bar', '--run-foo-bar']
        >>> marker2 = CustomMarker('foo', 'my desc')
        >>> marker2.option_flags()
        ['--run-foo']
        """
        # NOTE: pytest is not testing the above doctest
        # instead, run this file directly (see doctest.testmod at bottom)
        result = ['--run-{}'.format(self.name)]
        as_hyphen = '--run-{}'.format(self.name.replace('_', '-'))
        if as_hyphen != result[0]:
            result.append(as_hyphen)

        return result


CUSTOM_MARKERS = (
    CustomMarker('long',
                 'this test runs too long for Github Actions'),
    CustomMarker('uses_card',
                 'must have acceleration card installed to run test'),
)


def pytest_addoption(parser):
    """
    pytest hook - adds options to argument parser.
    """

    parser.addoption('--run-all',
                     dest='run_all',
                     action='store_true',
                     help='Run all tests normally skipped by default')

    for marker in CUSTOM_MARKERS:
        parser.addoption(*marker.option_flags(),
                         dest=marker.dest,
                         action='store_true',
                         help='Run tests marked with {}'.format(marker.name))


def pytest_configure(config):
    # Adds explicit marker definitions
    # with these, pytest will error if `--strict` is applied and unregistered
    # markers are present.
    for marker in CUSTOM_MARKERS:
        config.addinivalue_line("markers",
                                "{}: {}".format(marker.name, marker.desc))


def pytest_collection_modifyitems(config, items):
    """
    pytest hook which runs after tests have been collected.
    """
    skip_marked_tests(config, items)


def skip_marked_tests(config, items):
    """
    Dynamically applies pytest.mark.skip to tests with custom markers.

    Tests with explicit --run-FOO flags are not skipped.

    This keeps `pytest` from footshooting with tests that should only be run
    under particular conditions.
    """
    run_all = config.getoption('--run-all', default=False)
    run_mark = {marker.name: config.getoption(marker.dest)
                for marker in CUSTOM_MARKERS}

    for item in items:
        for marker_name, run_marker in run_mark.items():
            if marker_name in item.keywords and not (run_all or run_marker):
                item.add_marker(pytest.mark.skip)
                break
