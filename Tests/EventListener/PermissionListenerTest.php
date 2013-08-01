<?php

namespace Oneup\AclBundle\Tests\EventListener;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;

use Oneup\AclBundle\Annotation\AclCheck;
use Oneup\AclBundle\EventListener\PermissionListener;
use Oneup\AclBundle\Tests\Model\AbstractSecurityTest;
use Oneup\AclBundle\Tests\Model\TestController;
use Oneup\AclBundle\Tests\Model\SomeObject;

class PermissionListenerTest extends AbstractSecurityTest
{
    protected $listener;

    public function setUp()
    {
        parent::setUp();

        $manager = $this->getManager();
        $listener = new PermissionListener($manager);

        $this->listener = $listener;
    }

    /**
     * @expectedException Symfony\Component\Security\Core\Exception\AccessDeniedException
     */
    public function testAccessDenied()
    {
        $object = new SomeObject(1);

        $event = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\FilterControllerEvent')
            ->disableOriginalConstructor()
            ->getMock();

        $event->expects($this->any())
            ->method('getController')
            ->will($this->returnValue(array(
                new TestController,
                'oneAction'
            )))
        ;

        $checks = array(
            new AclCheck(array('value' => array('one' => 128)))
        );

        $request = new Request(array(), array(), array(
            '_acl_permission' => $checks,
            'one' => $object
        ));

        $event->expects($this->any())
            ->method('getRequest')
            ->will($this->returnValue($request))
        ;

        $this->listener->onKernelController($event);
    }

    public function testAccessGranted()
    {
        $object = new SomeObject(1);
        $this->manager->addObjectPermission($object, $this->getToken(), MaskBuilder::MASK_VIEW);

        $event = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\FilterControllerEvent')
            ->disableOriginalConstructor()
            ->getMock();

        $event->expects($this->any())
            ->method('getController')
            ->will($this->returnValue(array(
                new TestController,
                'oneAction'
            )))
        ;

        $checks = array(
            new AclCheck(array('value' => array('one' => 'VIEW')))
        );

        $request = new Request(array(), array(), array(
            '_acl_permission' => $checks,
            'one' => $object
        ));

        $event->expects($this->any())
            ->method('getRequest')
            ->will($this->returnValue($request))
        ;

        $this->listener->onKernelController($event);
    }
}