<?php

/*
 * UAF plugin for PocketMine-MP
 * Copyright (C) 2014 PocketMine Team <https://github.com/PocketMine/SimpleAuth>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
*/

namespace UAF\event;

use pocketmine\event\Cancellable;
use pocketmine\IPlayer;
use UAF\UAF;

class PlayerUnregisterEvent extends SimpleAuthEvent implements Cancellable{
	public static $handlerList = null;

	/** @var IPlayer */
	private $player;

	/**
	 * @param UAF $plugin
	 * @param IPlayer    $player
	 */
	public function __construct(UAF $plugin, IPlayer $player){
		$this->player = $player;
		parent::__construct($plugin);
	}

	/**
	 * @return IPlayer
	 */
	public function getPlayer(){
		return $this->player;
	}
}