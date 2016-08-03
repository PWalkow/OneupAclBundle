<?php

namespace Oneup\AclBundle\DependencyInjection\Compiler;

use Oneup\AclBundle\Security\Authorization\Acl\AclProvider;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Reference;

class MetaDataCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        if (!$container->hasDefinition('oneup_acl.driver_chain')) {
            return;
        }

        $definition = $container->getDefinition('oneup_acl.driver_chain');
        $services = $container->findTaggedServiceIds('oneup_acl.driver');

        foreach ($services as $id => $attributes) {
            $definition->addMethodCall('addDriver', array(new Reference($id)));
        }

        if ($container->hasDefinition('security.acl.dbal.provider')) {
            $definition = $container->getDefinition('security.acl.dbal.provider');
            $definition->setClass(AclProvider::class);
//            var_dump('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ overriden $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!');
        }
    }
}
