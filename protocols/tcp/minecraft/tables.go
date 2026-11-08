package minecraft

// Tables for protocol 772 (Java 1.21.7/1.21.8), the only version the open
// persona logs in. Registry entries come from misode/mcmeta 1.21.8-summary
// (registries/data.min.json), listed in vanilla's sorted registration order,
// which fixes the numeric IDs the client assigns. Registries follow vanilla's
// RegistrySynchronization send order. Packet names are Mojang's resource names,
// cross-checked between minecraft.wiki (Java Edition protocol/Packets, oldid
// 3258009) and PrismarineJS minecraft-data pc/1.21.8.

// syncedRegistries is what a 1.21.8 server sends in Registry Data, with entry
// data omitted because the client knows minecraft:core 1.21.8.
var syncedRegistries = []struct {
	ID      string
	Entries []string
}{
	{"minecraft:worldgen/biome", []string{
		"minecraft:badlands", "minecraft:bamboo_jungle", "minecraft:basalt_deltas", "minecraft:beach",
		"minecraft:birch_forest", "minecraft:cherry_grove", "minecraft:cold_ocean",
		"minecraft:crimson_forest", "minecraft:dark_forest", "minecraft:deep_cold_ocean",
		"minecraft:deep_dark", "minecraft:deep_frozen_ocean", "minecraft:deep_lukewarm_ocean",
		"minecraft:deep_ocean", "minecraft:desert", "minecraft:dripstone_caves", "minecraft:end_barrens",
		"minecraft:end_highlands", "minecraft:end_midlands", "minecraft:eroded_badlands",
		"minecraft:flower_forest", "minecraft:forest", "minecraft:frozen_ocean",
		"minecraft:frozen_peaks", "minecraft:frozen_river", "minecraft:grove", "minecraft:ice_spikes",
		"minecraft:jagged_peaks", "minecraft:jungle", "minecraft:lukewarm_ocean", "minecraft:lush_caves",
		"minecraft:mangrove_swamp", "minecraft:meadow", "minecraft:mushroom_fields",
		"minecraft:nether_wastes", "minecraft:ocean", "minecraft:old_growth_birch_forest",
		"minecraft:old_growth_pine_taiga", "minecraft:old_growth_spruce_taiga", "minecraft:pale_garden",
		"minecraft:plains", "minecraft:river", "minecraft:savanna", "minecraft:savanna_plateau",
		"minecraft:small_end_islands", "minecraft:snowy_beach", "minecraft:snowy_plains",
		"minecraft:snowy_slopes", "minecraft:snowy_taiga", "minecraft:soul_sand_valley",
		"minecraft:sparse_jungle", "minecraft:stony_peaks", "minecraft:stony_shore",
		"minecraft:sunflower_plains", "minecraft:swamp", "minecraft:taiga", "minecraft:the_end",
		"minecraft:the_void", "minecraft:warm_ocean", "minecraft:warped_forest",
		"minecraft:windswept_forest", "minecraft:windswept_gravelly_hills", "minecraft:windswept_hills",
		"minecraft:windswept_savanna", "minecraft:wooded_badlands",
	}},
	{"minecraft:chat_type", []string{
		"minecraft:chat", "minecraft:emote_command", "minecraft:msg_command_incoming",
		"minecraft:msg_command_outgoing", "minecraft:say_command", "minecraft:team_msg_command_incoming",
		"minecraft:team_msg_command_outgoing",
	}},
	{"minecraft:trim_pattern", []string{
		"minecraft:bolt", "minecraft:coast", "minecraft:dune", "minecraft:eye", "minecraft:flow",
		"minecraft:host", "minecraft:raiser", "minecraft:rib", "minecraft:sentry", "minecraft:shaper",
		"minecraft:silence", "minecraft:snout", "minecraft:spire", "minecraft:tide", "minecraft:vex",
		"minecraft:ward", "minecraft:wayfinder", "minecraft:wild",
	}},
	{"minecraft:trim_material", []string{
		"minecraft:amethyst", "minecraft:copper", "minecraft:diamond", "minecraft:emerald",
		"minecraft:gold", "minecraft:iron", "minecraft:lapis", "minecraft:netherite", "minecraft:quartz",
		"minecraft:redstone", "minecraft:resin",
	}},
	{"minecraft:wolf_variant", []string{
		"minecraft:ashen", "minecraft:black", "minecraft:chestnut", "minecraft:pale", "minecraft:rusty",
		"minecraft:snowy", "minecraft:spotted", "minecraft:striped", "minecraft:woods",
	}},
	{"minecraft:wolf_sound_variant", []string{
		"minecraft:angry", "minecraft:big", "minecraft:classic", "minecraft:cute", "minecraft:grumpy",
		"minecraft:puglin", "minecraft:sad",
	}},
	{"minecraft:pig_variant", []string{
		"minecraft:cold", "minecraft:temperate", "minecraft:warm",
	}},
	{"minecraft:frog_variant", []string{
		"minecraft:cold", "minecraft:temperate", "minecraft:warm",
	}},
	{"minecraft:cat_variant", []string{
		"minecraft:all_black", "minecraft:black", "minecraft:british_shorthair", "minecraft:calico",
		"minecraft:jellie", "minecraft:persian", "minecraft:ragdoll", "minecraft:red",
		"minecraft:siamese", "minecraft:tabby", "minecraft:white",
	}},
	{"minecraft:cow_variant", []string{
		"minecraft:cold", "minecraft:temperate", "minecraft:warm",
	}},
	{"minecraft:chicken_variant", []string{
		"minecraft:cold", "minecraft:temperate", "minecraft:warm",
	}},
	{"minecraft:painting_variant", []string{
		"minecraft:alban", "minecraft:aztec", "minecraft:aztec2", "minecraft:backyard",
		"minecraft:baroque", "minecraft:bomb", "minecraft:bouquet", "minecraft:burning_skull",
		"minecraft:bust", "minecraft:cavebird", "minecraft:changing", "minecraft:cotan",
		"minecraft:courbet", "minecraft:creebet", "minecraft:dennis", "minecraft:donkey_kong",
		"minecraft:earth", "minecraft:endboss", "minecraft:fern", "minecraft:fighters",
		"minecraft:finding", "minecraft:fire", "minecraft:graham", "minecraft:humble", "minecraft:kebab",
		"minecraft:lowmist", "minecraft:match", "minecraft:meditative", "minecraft:orb",
		"minecraft:owlemons", "minecraft:passage", "minecraft:pigscene", "minecraft:plant",
		"minecraft:pointer", "minecraft:pond", "minecraft:pool", "minecraft:prairie_ride",
		"minecraft:sea", "minecraft:skeleton", "minecraft:skull_and_roses", "minecraft:stage",
		"minecraft:sunflowers", "minecraft:sunset", "minecraft:tides", "minecraft:unpacked",
		"minecraft:void", "minecraft:wanderer", "minecraft:wasteland", "minecraft:water",
		"minecraft:wind", "minecraft:wither",
	}},
	{"minecraft:dimension_type", []string{
		"minecraft:overworld", "minecraft:overworld_caves", "minecraft:the_end", "minecraft:the_nether",
	}},
	{"minecraft:damage_type", []string{
		"minecraft:arrow", "minecraft:bad_respawn_point", "minecraft:cactus", "minecraft:campfire",
		"minecraft:cramming", "minecraft:dragon_breath", "minecraft:drown", "minecraft:dry_out",
		"minecraft:ender_pearl", "minecraft:explosion", "minecraft:fall", "minecraft:falling_anvil",
		"minecraft:falling_block", "minecraft:falling_stalactite", "minecraft:fireball",
		"minecraft:fireworks", "minecraft:fly_into_wall", "minecraft:freeze", "minecraft:generic",
		"minecraft:generic_kill", "minecraft:hot_floor", "minecraft:in_fire", "minecraft:in_wall",
		"minecraft:indirect_magic", "minecraft:lava", "minecraft:lightning_bolt", "minecraft:mace_smash",
		"minecraft:magic", "minecraft:mob_attack", "minecraft:mob_attack_no_aggro",
		"minecraft:mob_projectile", "minecraft:on_fire", "minecraft:out_of_world",
		"minecraft:outside_border", "minecraft:player_attack", "minecraft:player_explosion",
		"minecraft:sonic_boom", "minecraft:spit", "minecraft:stalagmite", "minecraft:starve",
		"minecraft:sting", "minecraft:sweet_berry_bush", "minecraft:thorns", "minecraft:thrown",
		"minecraft:trident", "minecraft:unattributed_fireball", "minecraft:wind_charge",
		"minecraft:wither", "minecraft:wither_skull",
	}},
	{"minecraft:banner_pattern", []string{
		"minecraft:base", "minecraft:border", "minecraft:bricks", "minecraft:circle",
		"minecraft:creeper", "minecraft:cross", "minecraft:curly_border", "minecraft:diagonal_left",
		"minecraft:diagonal_right", "minecraft:diagonal_up_left", "minecraft:diagonal_up_right",
		"minecraft:flow", "minecraft:flower", "minecraft:globe", "minecraft:gradient",
		"minecraft:gradient_up", "minecraft:guster", "minecraft:half_horizontal",
		"minecraft:half_horizontal_bottom", "minecraft:half_vertical", "minecraft:half_vertical_right",
		"minecraft:mojang", "minecraft:piglin", "minecraft:rhombus", "minecraft:skull",
		"minecraft:small_stripes", "minecraft:square_bottom_left", "minecraft:square_bottom_right",
		"minecraft:square_top_left", "minecraft:square_top_right", "minecraft:straight_cross",
		"minecraft:stripe_bottom", "minecraft:stripe_center", "minecraft:stripe_downleft",
		"minecraft:stripe_downright", "minecraft:stripe_left", "minecraft:stripe_middle",
		"minecraft:stripe_right", "minecraft:stripe_top", "minecraft:triangle_bottom",
		"minecraft:triangle_top", "minecraft:triangles_bottom", "minecraft:triangles_top",
	}},
	{"minecraft:enchantment", []string{
		"minecraft:aqua_affinity", "minecraft:bane_of_arthropods", "minecraft:binding_curse",
		"minecraft:blast_protection", "minecraft:breach", "minecraft:channeling", "minecraft:density",
		"minecraft:depth_strider", "minecraft:efficiency", "minecraft:feather_falling",
		"minecraft:fire_aspect", "minecraft:fire_protection", "minecraft:flame", "minecraft:fortune",
		"minecraft:frost_walker", "minecraft:impaling", "minecraft:infinity", "minecraft:knockback",
		"minecraft:looting", "minecraft:loyalty", "minecraft:luck_of_the_sea", "minecraft:lure",
		"minecraft:mending", "minecraft:multishot", "minecraft:piercing", "minecraft:power",
		"minecraft:projectile_protection", "minecraft:protection", "minecraft:punch",
		"minecraft:quick_charge", "minecraft:respiration", "minecraft:riptide", "minecraft:sharpness",
		"minecraft:silk_touch", "minecraft:smite", "minecraft:soul_speed", "minecraft:sweeping_edge",
		"minecraft:swift_sneak", "minecraft:thorns", "minecraft:unbreaking", "minecraft:vanishing_curse",
		"minecraft:wind_burst",
	}},
	{"minecraft:jukebox_song", []string{
		"minecraft:11", "minecraft:13", "minecraft:5", "minecraft:blocks", "minecraft:cat",
		"minecraft:chirp", "minecraft:creator", "minecraft:creator_music_box", "minecraft:far",
		"minecraft:lava_chicken", "minecraft:mall", "minecraft:mellohi", "minecraft:otherside",
		"minecraft:pigstep", "minecraft:precipice", "minecraft:relic", "minecraft:stal",
		"minecraft:strad", "minecraft:tears", "minecraft:wait", "minecraft:ward",
	}},
	{"minecraft:instrument", []string{
		"minecraft:admire_goat_horn", "minecraft:call_goat_horn", "minecraft:dream_goat_horn",
		"minecraft:feel_goat_horn", "minecraft:ponder_goat_horn", "minecraft:seek_goat_horn",
		"minecraft:sing_goat_horn", "minecraft:yearn_goat_horn",
	}},
	{"minecraft:test_environment", []string{
		"minecraft:default",
	}},
	{"minecraft:test_instance", []string{
		"minecraft:always_pass",
	}},
	{"minecraft:dialog", []string{
		"minecraft:custom_options", "minecraft:quick_actions", "minecraft:server_links",
	}},
}

// configServerbound names the configuration-state serverbound packet IDs.
var configServerbound = []string{
	"client_information",   // 0x00
	"cookie_response",      // 0x01
	"custom_payload",       // 0x02
	"finish_configuration", // 0x03
	"keep_alive",           // 0x04
	"pong",                 // 0x05
	"resource_pack",        // 0x06
	"select_known_packs",   // 0x07
	"custom_click_action",  // 0x08
}

// playServerbound names the play-state serverbound packet IDs.
var playServerbound = []string{
	"accept_teleportation",         // 0x00
	"block_entity_tag_query",       // 0x01
	"bundle_item_selected",         // 0x02
	"change_difficulty",            // 0x03
	"change_game_mode",             // 0x04
	"chat_ack",                     // 0x05
	"chat_command",                 // 0x06
	"chat_command_signed",          // 0x07
	"chat",                         // 0x08
	"chat_session_update",          // 0x09
	"chunk_batch_received",         // 0x0A
	"client_command",               // 0x0B
	"client_tick_end",              // 0x0C
	"client_information",           // 0x0D
	"command_suggestion",           // 0x0E
	"configuration_acknowledged",   // 0x0F
	"container_button_click",       // 0x10
	"container_click",              // 0x11
	"container_close",              // 0x12
	"container_slot_state_changed", // 0x13
	"cookie_response",              // 0x14
	"custom_payload",               // 0x15
	"debug_sample_subscription",    // 0x16
	"edit_book",                    // 0x17
	"entity_tag_query",             // 0x18
	"interact",                     // 0x19
	"jigsaw_generate",              // 0x1A
	"keep_alive",                   // 0x1B
	"lock_difficulty",              // 0x1C
	"move_player_pos",              // 0x1D
	"move_player_pos_rot",          // 0x1E
	"move_player_rot",              // 0x1F
	"move_player_status_only",      // 0x20
	"move_vehicle",                 // 0x21
	"paddle_boat",                  // 0x22
	"pick_item_from_block",         // 0x23
	"pick_item_from_entity",        // 0x24
	"ping_request",                 // 0x25
	"place_recipe",                 // 0x26
	"player_abilities",             // 0x27
	"player_action",                // 0x28
	"player_command",               // 0x29
	"player_input",                 // 0x2A
	"player_loaded",                // 0x2B
	"pong",                         // 0x2C
	"recipe_book_change_settings",  // 0x2D
	"recipe_book_seen_recipe",      // 0x2E
	"rename_item",                  // 0x2F
	"resource_pack",                // 0x30
	"seen_advancements",            // 0x31
	"select_trade",                 // 0x32
	"set_beacon",                   // 0x33
	"set_carried_item",             // 0x34
	"set_command_block",            // 0x35
	"set_command_minecart",         // 0x36
	"set_creative_mode_slot",       // 0x37
	"set_jigsaw_block",             // 0x38
	"set_structure_block",          // 0x39
	"set_test_block",               // 0x3A
	"sign_update",                  // 0x3B
	"swing",                        // 0x3C
	"teleport_to_entity",           // 0x3D
	"test_instance_block_action",   // 0x3E
	"use_item_on",                  // 0x3F
	"use_item",                     // 0x40
	"custom_click_action",          // 0x41
}
