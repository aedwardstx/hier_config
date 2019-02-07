class RemediationFixupBase(object):

    def __init__(self, host):
        self.host = host

    def run(self, tags):
        """
        Only run the remediation fixup if there is an intersection between the tags passed to this method
        and tags from the resulting scenarios.
        :param tags:
        :return:
        """
        if self.is_relevant(tags):
            self._run()

    def is_relevant(self, tags):
        if self.is_compatible:
            if 'all' in tags or self.tags.intersection(tags):
                return True
        return False

    @property
    def tags(self):
        tags = set()
        for scenario in self.scenarios.values():
            tags.update(scenario[tags])
        return tags

    @property
    def scenarios(self):
        raise NotImplementedError

    def is_compatible(self):
        raise NotImplementedError

    def _apply_scenario(self, name, hier_obj, new_text=None):
        """
        Applied a scenario to a hier_config object in a specified way

        :param name: scenario name
        :param hier_obj: the remediation config hier_obj for the node to act on
        :return: HierConfig
        """
        action_to_function = {
            'add_to_children': hier_obj.apply_tags_deep,
            'add_to_node': hier_obj.apply_tags,
            'add_to_parents': hier_obj.apply_tags_ancestors,
        }

        if new_text:
            hier_obj.text = new_text
        scenario = self.scenarios[name]
        tags = scenario['tags']
        comments = scenario['comments']
        actions = scenario['actions']
        for action in actions:
            action_to_function[action](tags)

        hier_obj.comments.update(comments)
        return hier_obj

    def _apply_scenario_via_rules(self, name, hier_obj, rules):
        """
        Applies a scenario using tag rules
        The outer list: A rule set,
        The inner dicts:

        rules = [
                    {
                        'startswith': ['interface '],
                    },
                    {
                        'startswith': ['ip address '],
                    },
                ]


        :param name: Scenario name to apply
        :param hier_obj: The hier_config object to act against
        :param rules:
        :return:
        """
        for rule in rules:
            for child in hier_obj.all_children():
                if child.lineage_test(rule, False):
                    self._apply_scenario(name, child)

    @property
    def _run(self):
        raise NotImplementedError

