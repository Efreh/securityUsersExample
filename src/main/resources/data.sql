-- Вставка начальных записей
INSERT INTO users (username, password, role, is_account_non_locked) VALUES
    ('user', '$2b$12$/650U7FM98iNSJo2JGXrfOVWUsjosVGufMUeVft0DJillKTqXiPuK', 'USER', TRUE),
    ('moderator', '$2b$12$56RF.1jMcHyKPOHMTOJw7OxJsGGUkZKnBgfAvP96B0WlfccZj3pya', 'MODERATOR', TRUE),
    ('super_admin', '$2b$12$oNNn.DqO.SVHj0JsWSEeBeIaWFcTiaAH7fgz9HRL94FKfLiZajzwS', 'SUPER_ADMIN', TRUE);
