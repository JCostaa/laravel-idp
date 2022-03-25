<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AbstractController extends Controller
{
    public function redirectToSP()
    {
        $issuer='https://ec2-54-205-120-69.compute-1.amazonaws.com/saml/metadata';
        $acsUrl='https://ec2-54-174-48-59.compute-1.amazonaws.com/module.php/saml/sp/saml2-acs.php/default-sp';

        $attributes = [
            'firstName' => [
                'format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                'name' => 'firstname',
                'value' => 'Bob'
            ],
            'lastName' => [
                'format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                'name' => 'lastname',
                'value' => 'Dylan'
            ],
            'email' => [
                'format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                'name' => 'email',
                'value' => 'student@test.com'
            ],
            'title' => [
                'format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
                'name' => 'title',
                'value' => '1'
            ],
        ];

        // Preparing the response XML
        $serializationContext = new \LightSaml\Model\Context\SerializationContext();

        // We now start constructing the SAML Response using LightSAML.
        $response = new \LightSaml\Model\Protocol\Response();
        $response
            ->addAssertion($assertion = new \LightSaml\Model\Assertion\Assertion())
            ->setStatus(new \LightSaml\Model\Protocol\Status(
                    new \LightSaml\Model\Protocol\StatusCode(
                        \LightSaml\SamlConstants::STATUS_SUCCESS)
                )
            )
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($acsUrl)
            // We obtain the Entity ID from the Idp.
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer))
        ;

        $assertion
            ->setId(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            // We obtain the Entity ID from the Idp.
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer))
            ->setSubject(
                (new \LightSaml\Model\Assertion\Subject())
                    // Here we set the NameID that identifies the name of the user.
                    ->setNameID(new \LightSaml\Model\Assertion\NameID(
                        \LightSaml\Helper::generateID(),
                        \LightSaml\SamlConstants::NAME_ID_FORMAT_UNSPECIFIED
                    ))
                    ->addSubjectConfirmation(
                        (new \LightSaml\Model\Assertion\SubjectConfirmation())
                            ->setMethod(\LightSaml\SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new \LightSaml\Model\Assertion\SubjectConfirmationData())
                                    // We set the ResponseTo to be the id of the SAMLRequest.
                                    ->setInResponseTo(\LightSaml\Helper::generateID())
                                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                    // The recipient is set to the Service Provider ACS.
                                    ->setRecipient($acsUrl)
                            )
                    )
            )
            ->setConditions(
                (new \LightSaml\Model\Assertion\Conditions())
                    ->setNotBefore(new \DateTime())
                    ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                    ->addItem(
                    // Use the Service Provider Entity ID as AudienceRestriction.
                        new \LightSaml\Model\Assertion\AudienceRestriction(['https://simplesamlphp-sp1/module.php/saml/sp/metadata.php/default-sp'])
                    )
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        $attributes['firstName']['name'],
                        $attributes['firstName']['value']
                    ))
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        $attributes['lastName']['name'],
                        $attributes['lastName']['value']
                    ))
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        $attributes['email']['name'],
                        $attributes['email']['value']
                    ))
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        $attributes['title']['name'],
                        $attributes['title']['value']
                    ))
            )
            ->addItem(
                (new \LightSaml\Model\Assertion\AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                    ->setSessionIndex($assertion->getId())
                    ->setAuthnContext(
                        (new \LightSaml\Model\Assertion\AuthnContext())
                            ->setAuthnContextClassRef(\LightSaml\SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                    )
            )
        ;

        // Sign the response.
        $response->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter(
                \LightSaml\Credential\X509Certificate::fromFile(storage_path('samlidp/cert.pem')),
                \LightSaml\Credential\KeyHelper::createPrivateKey(storage_path('samlidp/key.pem'), '', true)
            )
        );

        // Serialize to XML.
        $response->serialize($serializationContext->getDocument(), $serializationContext);

        // Set the postback url obtained from the trusted SPs as the destination.
        $response->setDestination($acsUrl);

        return $this->sendSAMLResponseTwo($response);
    }

    private function sendSAMLResponseTwo($response)
    {
        $bindingFactory = new \LightSaml\Binding\BindingFactory();
        $postBinding = $bindingFactory->create(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST);
        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($response)->asResponse();
        $httpResponse = $postBinding->send($messageContext);



        return $httpResponse->getContent();
    }
}
