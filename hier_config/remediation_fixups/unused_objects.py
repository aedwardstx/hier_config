from hier_config.remediation_fixups import RemediationFixupBase


class RemediationUnusedObjects(RemediationFixupBase):
    scenarios = {
        'unused_object': {
            'tags': ('safe', 'unused_object'),
            'comments': ('unused object',),
            'actions': ('node',),
        },
    }

    @property
    def _os_cases(self):
        return {
            'ios': self._case_ios,
            'eos': self._case_eos,
            'iosxr': self._case_iosxr,
            'nxos': self._case_nxos,
        }

    def _run(self):
        try:
            self._os_cases[self.host.os]()
        except KeyError:
            pass

    def is_compatible(self):
        if self.host.os in self._os_cases.keys():
            return True
        return False

    def _case_ios(self):
        objects = (
            'ip prefix-list ',
            'ipv6 access-list ',
            'ip as-path access-list ',
            'ipv6 prefix-list ',
            'ipv6 general-prefix ',
            'route-map ',
            'ip access-list extended ',
            'class-map match-any ',
            'class-map match-all ',
        )
        for obj in objects:
            self._unused_object_common_logic(obj)

    def _case_eos(self):
        objects = (
            'ip prefix-list ',
            'ipv6 access-list ',
            'ip as-path access-list ',
            'ipv6 prefix-list ',
            'route-map ',
            'ip access-list extended ',
            'class-map match-any ',
            'class-map match-all ',
        )
        for obj in objects:
            self._unused_object_common_logic(obj)

    def _case_nxos(self):
        objects = (
            'object-group ip port ',
            'object-group ipv6 port ',
            'object-group ip address ',
            'object-group ipv6 address ',
            'ip prefix-list ',
            'ipv6 access-list ',
            'ip as-path access-list ',
            'ipv6 prefix-list ',
            'route-map ',
            'ip access-list ',
        )
        for obj in objects:
            self._unused_object_common_logic(obj)

    def _case_iosxr(self):
        objects = (
            'route-policy',
            'community-set',
            'extcommunity-set rt',
            'extcommunity-set soo',
            'ipv4 access-list',
            'ipv6 access-list',
            'class-map match-any',
            'class-map match-all',
            'policy-map',
        )
        for obj in objects:
            self._unused_object_common_logic(obj)

    def _unused_object_common_logic(self, object_prefix):
        """
        """
        rc_objects = self.host.facts['running_config'].get_children('startswith', f'{object_prefix} ')
        for rc_object in rc_objects:
            object_name = rc_object.text.split()[len(object_prefix.split())]
            # Strip args e.g. route-policy RCG-CE-PRI-IPV4-IN($CUSTOMERPFX)
            object_name = object_name.split('(', 1)[0]
            # object_name = re.sub('\(.*\)$', '', object_name)
            neg_text = f'no {rc_object.text}'
            cp_neg_object = self.host.facts['remediation'].get_child('equals', neg_text)
            if cp_neg_object is None:
                continue

            if self._used_object_check(object_prefix, object_name):
                self._apply_scenario('unused_object', cp_neg_object, new_text=f'no {object_prefix} {object_name}')

    def _used_object_check(self, object_prefix, object_name):
        """
        Checks if an object(acl, route-map, prefix-list, etc.) is
        used elsewhere in the config.
        """
        for child in self.host.facts['running_config'].all_children():
            if child.depth() == 1 and child.text.startswith(object_prefix):
                continue
            elif ' {} '.format(object_name) in child.text:
                return False
            elif ' {}('.format(object_name) in child.text:
                return False
            elif child.text.endswith(' {}'.format(object_name)):
                return False
        return True
