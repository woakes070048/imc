<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
/**
 * @version     3.0.1
 * @package     com_imc
 * @copyright   Copyright (C) 2026. All rights reserved.
 * @license     GNU AFFERO GENERAL PUBLIC LICENSE Version 3; see LICENSE
 * @author      Ioannis Tsampoulatidis <tsampoulatidis@gmail.com> - https://github.com/itsam
 */

// No direct access.
defined('_JEXEC') or die;

require_once JPATH_COMPONENT . '/controller.php';
require_once JPATH_COMPONENT_SITE . '/helpers/imc.php';
require_once JPATH_COMPONENT_SITE . '/helpers/MCrypt2.php';
require_once JPATH_COMPONENT_SITE . '/models/tokens.php';
require_once JPATH_COMPONENT_SITE . '/controllers/comments.json.php';

/**
 * IMC API 3 controller class.
 * this controller is used only by 2026 Android app during migration phase 
 */

class ImcControllerApi3 extends ImcController
{
	private $mcrypt;
	private $keyModel;
	private $params;

	function __construct()
	{
		$this->params = JComponentHelper::getParams('com_imc');
		$this->mcrypt = new MCrypt();
		JModelLegacy::addIncludePath(JPATH_COMPONENT_ADMINISTRATOR . '/models');
		$this->keyModel = JModelLegacy::getInstance('Key', 'ImcModel', array('ignore_request' => true));
		parent::__construct();
	}

	public function exception_error_handler($errno, $errstr, $errfile, $errline)
	{
		$ee = new ErrorException($errstr, 0, $errno, $errfile, $errline);
		JFactory::getApplication()->enqueueMessage($ee, 'error');
		throw $ee;
	}

	private function valid_email($email)
	{
		return !!filter_var($email, FILTER_VALIDATE_EMAIL);
	}

	private function validateRequest($isNew = false)
	{
		$app = JFactory::getApplication();
		$token = $app->input->getString('token');
		$m_id  = $app->input->getInt('m_id');
		$l     = $app->input->getString('l');

		//1. check necessary arguments are exist
		if (is_null($token) || is_null($m_id) || is_null($l)) {
			$app->enqueueMessage('Either, token, m_id (modality), or l (language) are missing', 'error');
			throw new Exception('Request is invalid');
		}

		//set language
		ImcFrontendHelper::setLanguage($app->input->getString('l'), array('com_users', 'com_imc'));

		//check for nonce (existing token)
		if ($this->params->get('advancedsecurity')) {
			if (ImcModelTokens::exists($token)) {
				throw new Exception('Token is already used');
			}
		}
		//2. get the appropriate key according to given modality
		$result = $this->keyModel->getItem($m_id);
		$key = $result->skey;
		if (strlen($key) < 16) {
			$app->enqueueMessage('Secret key is not 16 characters', 'error');
			throw new Exception('Secret key is invalid. Contact administrator');
		} else {
			$this->mcrypt->setKey($key);
		}

		//3. decrypt and check token validity
		$decryptedToken = $this->mcrypt->decrypt($token);
		$decryptedToken = base64_decode($decryptedToken);
		$objToken = json_decode($decryptedToken);

		if (!is_object($objToken)) {
			throw new Exception('Token is invalid');
		}

		//if (!isset($objToken->u) || !isset($objToken->p) || !isset($objToken->t) || !isset($objToken->r)) {
		if (!isset($objToken->u) || !isset($objToken->p)) {
			throw new Exception('Token is not well formatted');
		}

		if ($this->params->get('advancedsecurity')) {
			if ((time() - $objToken->t) > 3 * 60) {
				throw new Exception('Token has expired');
			}
		}

		//4. authenticate user
		$userid = 0;
		if (self::valid_email($objToken->u)) {
			//b. get userid given email
			$db = JFactory::getDbo();
			$query = $db->getQuery(true);
			$query->select('id');
			$query->from('#__users');
			$query->where('UPPER(email) = UPPER(' . $db->Quote($objToken->u) . ')');
			$db->setQuery($query);
			$result = $db->loadObject();
			$userid = $result->id;
		} else {
			//a. get userid given username
			$userid = JUserHelper::getUserId($objToken->u);
		}

		$user = JFactory::getUser($userid);
		$userInfo = array();
		if ($isNew) {
			$userInfo['username'] = $objToken->u;
			$userInfo['password'] = $objToken->p;
		} else {
			if ($objToken->u == 'imc-guest' && $objToken->p == 'imc-guest') {
				$userid = 0;
			} else {
				$match = JUserHelper::verifyPassword($objToken->p, $user->password, $userid);
				if (!$match) {
					$app->enqueueMessage(JText::_('COM_IMC_API_USERNAME_PASSWORD_NO_MATCH'), 'error');
					throw new Exception('Token does not match');
				}
				if ($user->block) {
					$app->enqueueMessage(JText::_('COM_IMC_API_USER_NOT_ACTIVATED'), 'error');
					throw new Exception(JText::_('COM_IMC_API_USER_BLOCKED'));
				}
			}
		}

		//5. populate token table
		if ($this->params->get('advancedsecurity')) {
			$record = new stdClass();
			$record->key_id = $m_id;
			$record->user_id = $userid;
			//$record->json_size = $json_size;
			$record->method = $app->input->getMethod();
			$record->token = $token;
			$record->unixtime = $objToken->t;
			ImcModelTokens::insertToken($record); //this static method throws exception on error
		}

		return $isNew ? $userInfo : (int) $userid;
	}

    public function hello()
	{
		$result = null;
		$app = JFactory::getApplication();
		try {
			//get necessary arguments
			$m_id  = $app->input->getInt('m_id', 2);

			switch ($app->input->getMethod()) {

				case 'GET':
					$result = array('message' => 'Hello from IMC API 3', 'modality' => $m_id);
					break;
				default:
					throw new Exception('HTTP method is not supported');
			}
			header('Content-type: application/json');
			echo new JResponseJson($result, 'Hello action completed successfully');
			exit();
		} catch (Exception $e) {
			header("HTTP/1.0 202 Accepted");
			header('Content-type: application/json');
			echo new JResponseJson($e);
			exit();
		}
	}


	public function issue3()
	{
		$result = null;
		$app = JFactory::getApplication();
		try {
			//get necessary arguments
			$userid = $app->input->getInt('userid', 0);
			$id = $app->input->getInt('id', null);
			$m_id  = $app->input->getInt('modality', 2);

			switch ($app->input->getMethod()) {

				case 'POST':
					// header('Content-type: application/json');
					// $result = $_FILES;
					// echo new JResponseJson($result, 'Issue action completed successfully');
					if ($id != null) {
						throw new Exception('You cannot use POST to fetch issue. Use GET instead');
					}

					//guests are not allowed to post issues
					//TODO: get this from settings
					if ($userid == 0) {
						throw new Exception(JText::_('COM_IMC_API_NO_GUESTS_NO_POST'));
					}

					//get necessary arguments
					$args = array(
						'catid' => $app->input->getInt('catid'),
						'title' => $app->input->getString('title'),
						'description' => $app->input->getString('description'),
						'address' => $app->input->getString('address'),
						'latitude' => $app->input->getString('lat'),
						'longitude' => $app->input->getString('lng'),
						'district' => $app->input->getInt('district', 1),
						'extra' => $app->input->getString('extra', '')
					);
					ImcFrontendHelper::checkNullArguments($args);

					//check if category exists
					if (is_null(ImcFrontendHelper::getCategoryNameByCategoryId($args['catid'], true))) {
						throw new Exception(JText::_('COM_IMC_API_CATEGORY_NOT_EXIST'));
					}

					$args['userid'] = $userid;
					$args['created_by'] = $userid;
					$args['stepid'] = ImcFrontendHelper::getPrimaryStepId();
					$args['id'] = 0;
					$args['created'] = ImcFrontendHelper::convert2UTC(date('Y-m-d H:i:s'));
					$args['updated'] = $args['created'];
					$args['note'] = 'modality=' . $m_id;
					$args['language'] = '*';
					$args['subgroup'] = 0;
					$args['modality'] = $m_id;

					$tmpTime = time(); //used for temporary id
					$imagedir = 'images/imc';

					//check if post contains files
					$file = $app->input->files->get('files');
					if (!empty($file)) {
						require_once JPATH_ROOT . '/components/com_imc/models/fields/multiphoto/server/UploadHandler.php';
						$options = array(
							'script_url' => JRoute::_(JURI::root(true) . '/administrator/index.php?option=com_imc&task=upload.handler&format=json&id=' . $tmpTime . '&imagedir=' . $imagedir . '&' . JSession::getFormToken() . '=1'),
							'upload_dir' => JPATH_ROOT . '/' . $imagedir . '/' . $tmpTime . '/',
							'upload_url' => $imagedir . '/' . $tmpTime . '/',
							'param_name' => 'files',
							'imc_api' => true

						);
						$upload_handler = new UploadHandler($options);
						if (isset($upload_handler->imc_api)) {
							$files_json = json_decode($upload_handler->imc_api);
							$args['photo'] = json_encode(array('isnew' => 1, 'id' => $tmpTime, 'imagedir' => $imagedir, 'files' => $files_json->files));
							$app->enqueueMessage('File(s) uploaded successfully', 'info');
						} else {
							throw new Exception(JText::_('COM_IMC_API_UPLOAD_FAILED'));
						}
					} else {
						$args['photo'] = json_encode(array('isnew' => 1, 'id' => $tmpTime, 'imagedir' => $imagedir, 'files' => array()));
					}

					//get issueForm model and save
					$issueFormModel = JModelLegacy::getInstance('IssueForm', 'ImcModel', array('ignore_request' => true));

					//handle unexpected warnings from model
					set_error_handler(array($this, 'exception_error_handler'));
					$issueFormModel->save($args);
					$insertid = JFactory::getApplication()->getUserState('com_imc.edit.issue.insertid');

					//call post save hook
					require_once JPATH_COMPONENT . '/controllers/issueform.php';
					$issueFormController = new ImcControllerIssueForm();
					$issueFormController->postSaveHook($issueFormModel, $args);
					restore_error_handler();

					$result = array('issueid' => $insertid);

					//be consistent return as array (of size 1)
					$result = array($result);

					break;
				default:
					throw new Exception('HTTP method is not supported');
			}
			header('Content-type: application/json');
			echo new JResponseJson($result, 'Issue action completed successfully');
			exit();
		} catch (Exception $e) {
			header("HTTP/1.0 202 Accepted");
			header('Content-type: application/json');
			echo new JResponseJson($e);
			exit();
		}
	}



	private function raw_json_encode($input, $flags = 0)
	{
		$fails = implode('|', array_filter(array(
			'\\\\',
			$flags & JSON_HEX_TAG ? 'u003[CE]' : '',
			$flags & JSON_HEX_AMP ? 'u0026' : '',
			$flags & JSON_HEX_APOS ? 'u0027' : '',
			$flags & JSON_HEX_QUOT ? 'u0022' : '',
		)));
		$pattern = "/\\\\(?:(?:$fails)(*SKIP)(*FAIL)|u([0-9a-fA-F]{4}))/";
		$callback = function ($m) {
			return html_entity_decode("&#x$m[1];", ENT_QUOTES, 'UTF-8');
		};
		return preg_replace_callback($pattern, $callback, json_encode($input, $flags));
	}
}
