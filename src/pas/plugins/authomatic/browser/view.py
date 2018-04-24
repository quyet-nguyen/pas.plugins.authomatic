# -*- coding: utf-8 -*-
from authomatic import Authomatic
from pas.plugins.authomatic.integration import ZopeRequestAdapter
from pas.plugins.authomatic.interfaces import _
from pas.plugins.authomatic.utils import authomatic_plugin, authomatic_cfg, authomatic_settings
from plone import api
from plone.app.layout.navigation.interfaces import INavigationRoot
from plone.protect.interfaces import IDisableCSRFProtection
from Products.CMFCore.interfaces import ISiteRoot
from Products.Five.browser import BrowserView
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from zope.interface import alsoProvides
from zope.interface import implementer
from zope.publisher.interfaces import IPublishTraverse

import logging


logger = logging.getLogger(__file__)


@implementer(IPublishTraverse)
class AuthomaticView(BrowserView):

    template = ViewPageTemplateFile('authomatic.pt')

    def publishTraverse(self, request, name):
        if name and not hasattr(self, 'provider'):
            self.provider = name
        return self

    def providers(self):
        for identifier, cfg in self.cfgs.items():
            entry = cfg.get('display', {})
            cssclasses = entry.get('cssclasses', {})
            record = {
                'identifier': identifier,
                'title': entry.get('title', identifier),
                'iconclasses': cssclasses.get(
                    'icon',
                    'glypicon glyphicon-log-in'
                ),
                'buttonclasses': cssclasses.get(
                    'button',
                    'plone-btn plone-btn-default'
                ),
                'as_form': entry.get('as_form', False),
            }
            yield record

    def _add_identity(self, result, provider_name):
        # delegate to PAS plugin to add the identity
        alsoProvides(self.request, IDisableCSRFProtection)
        self.authopas.remember_identity(result, userid=self.user.id)
        api.portal.show_message(
            _(
                'added_identity',
                default='Added identity provided by ${provider}',
                mapping={'provider': provider_name}
            ),
            self.request
        )

    def _remember_identity(self, result, provider_name):
        alsoProvides(self.request, IDisableCSRFProtection)
        self.authopas.remember(result)
        api.portal.show_message(
            _(
                'logged_in_with',
                'Logged in with ${provider}',
                mapping={'provider': provider_name}
            ),
            self.request
        )

    def __call__(self):

        # callback url is expected on site root
        if not ISiteRoot.providedBy(self.context):
            root = api.portal.get()
            self.request.response.redirect(
                "{0}/authomatic-handler/{1}".format(
                    root.absolute_url(),
                    getattr(self, 'provider', '')
                )
            )
            return "redirecting"

        self.authopas = authomatic_plugin()
        self.cfgs = authomatic_cfg()
        if self.cfgs is None:
            return "Authomatic is not configured"
        self.is_anon = api.user.is_anonymous()
        if not self.is_anon:
            self.user = api.user.get_current()
            self.user_providers = self.authopas._useridentities_by_userid.get(self.user.id).providers()

        # Validate provider
        if not hasattr(self, 'provider'):
            return self.template()
        if self.provider not in self.cfgs:
            return "Provider not supported"
        if not self.is_anon and self.provider in self.user_providers:
            action = self.request.form.get('action', None)
            if action == 'unlink':
                alsoProvides(self.request, IDisableCSRFProtection)
                self.authopas.remove_identity(self.user.id, self.provider)
                api.portal.show_message(
                    _(
                        'Unlink account with {provider} provider',
                        mapping={'provider': self.provider}
                    ),
                    self.request
                )
                return self.template()
            #Any other action ?
            else:
                api.portal.show_message(
                    _(
                        'Provider {provider} is already connected to current user',
                        mapping={'provider': self.provider}
                    ),
                    self.request
                )
                return self.template()

            # TODO: some sort of CSRF check might be needed, so that
            #       not an account got connected by CSRF. Research needed.

        #Authomatic login
        auth = Authomatic(
            self.cfgs,
            secret=authomatic_settings().secret.encode('utf8')
        )
        result = auth.login(
            ZopeRequestAdapter(self),
            self.provider
        )
        if not result:
            logger.info('return from view')
            # let authomatic do its work
            return
        if result.error:
            return result.error.message
        # fetch provider specific user-data
        result.user.update()

        display = self.cfgs[self.provider].get('display', {})
        provider_name = display.get('title', self.provider)
        if not self.is_anon:
            # now we delegate to PAS plugin to add the identity
            self._add_identity(result, provider_name)
            self.request.response.redirect(
                "{0}".format(self.context.absolute_url())
            )
        else:
            # now we delegate to PAS plugin in order to login
            self._remember_identity(result, provider_name)
            self.request.response.redirect(
                "{0}/login_success".format(self.context.absolute_url())
            )
        return "redirecting"

