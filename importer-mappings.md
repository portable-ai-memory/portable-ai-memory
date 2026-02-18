# PAM Importer Field Mappings — Provider → Normalized Conversation

**Status:** Based on verified real exports (Feb 2026). Covers OpenAI, Anthropic, Google, Microsoft, xAI.<br>
**WARNING:** Provider export formats change without notice. Importers MUST be versioned.

---

## 1. OpenAI (ChatGPT)

**Source:** Settings → Data Controls → Export Data (delivered via email as ZIP)
**Structure:** Single JSON array of conversation objects. Messages in `mapping` as DAG.
**Timestamp format:** Unix epoch (float seconds)
**Verified against:** Official OpenAI documentation and community-verified export structures

### Export files

The ChatGPT export ZIP contains:

| File                        | Description                                                 |
|-----------------------------|-------------------------------------------------------------|
| `conversations.json`        | All conversation history as a JSON array with DAG structure |
| `chat.html`                 | Human-readable version (renders JSON via client-side JS)    |
| `user.json`                 | Account metadata (id, email, phone, plan)                   |
| `message_feedback.json`     | Thumbs-up/down ratings with text descriptions               |
| `shared_conversations.json` | Conversations shared via public link                        |
| `tool_messages.json`        | Tool-related responses and metadata                         |
| `*.dat`                     | DALL-E image assets (actually PNG files with C2PA metadata) |

> **Note:** ChatGPT memories (Settings → Capabilities → Memory) are **NOT included** in the data
> export as of Feb 2026. This is a known gap — there is no `memories.json` or equivalent file.

### Conversation-level mapping

| Provider field | PAM field                  | Transform                                       |
|----------------|----------------------------|-------------------------------------------------|
| `id`           | `provider.conversation_id` | direct                                          |
| `title`        | `title`                    | direct                                          |
| `create_time`  | `temporal.created_at`      | `datetime.fromtimestamp(v, tz=UTC).isoformat()` |
| `update_time`  | `temporal.updated_at`      | `datetime.fromtimestamp(v, tz=UTC).isoformat()` |
| —              | `provider.name`            | hardcode `"chatgpt"`                            |

### Message-level mapping

Messages are in `mapping[message_id]`, NOT a flat array.

| Provider field                            | PAM field                           | Transform                                                                |
|-------------------------------------------|-------------------------------------|--------------------------------------------------------------------------|
| `mapping[k].id`                           | `provider_message_id`               | direct                                                                   |
| `mapping[k].id`                           | `id`                                | generate UUID or use original                                            |
| `mapping[k].parent`                       | `parent_id`                         | map provider ID → PAM ID                                                 |
| `mapping[k].children`                     | `children_ids`                      | map provider IDs → PAM IDs                                               |
| `mapping[k].message.author.role`          | `role`                              | `user`→`user`, `assistant`→`assistant`, `system`→`system`, `tool`→`tool` |
| `mapping[k].message.content.content_type` | `content.type`                      | `"text"`→`"text"`, `"multimodal_text"`→`"multipart"`                     |
| `mapping[k].message.content.parts[]`      | `content.text` or `content.parts[]` | join parts for text, split for multipart                                 |
| `mapping[k].message.create_time`          | `created_at`                        | Unix epoch → ISO 8601                                                    |
| `mapping[k].message.metadata.model_slug`  | `model`                             | direct if present                                                        |

### Critical notes

- **DAG structure**: `mapping` is a graph, not a list. Some conversations have multiple root nodes or orphaned messages.
- **Null messages**: Some mapping entries have `message: null`. Skip these.
- **Timestamps**: Some messages have `create_time: 0` or `null`. Use conversation-level timestamp as fallback.
- **Content parts**: `parts[]` may contain strings, dicts (for images), or `null` entries. Filter nulls.
- **System messages**: Often hidden, contain model instructions.
- **DALL-E metadata**: Image generation data is in `message.metadata` with `request_id` linking to generation results.

---

## 2. Anthropic (Claude)

**Source:** `conversations.json` (from Settings → Privacy → Export Data)
**Structure:** Single JSON array of conversation objects. Messages in `chat_messages` as flat array.
**Timestamp format:** ISO 8601
**Verified against:** Real export from Feb 2026 (90 conversations, 5134 content parts)

### Export files

The Claude export ZIP contains 4 files:

| File                 | Description                                                                              |
|----------------------|------------------------------------------------------------------------------------------|
| `conversations.json` | Array of conversation objects with `chat_messages`                                       |
| `memories.json`      | User memories — `conversations_memory` (string) + `project_memories` (dict of UUID→text) |
| `projects.json`      | Projects — `uuid`, `name`, `description`, `prompt_template`, `docs`, `creator`           |
| `users.json`         | Account info — `uuid`, `full_name`, `email_address`, `verified_phone_number`             |

### Conversation-level mapping

| Provider field | PAM field                  | Transform                 |
|----------------|----------------------------|---------------------------|
| `uuid`         | `provider.conversation_id` | direct                    |
| `name`         | `title`                    | direct                    |
| `summary`      | `raw_metadata.summary`     | preserve in raw_metadata  |
| `created_at`   | `temporal.created_at`      | direct (already ISO 8601) |
| `updated_at`   | `temporal.updated_at`      | direct                    |
| `account.uuid` | `provider.account_id`      | direct                    |
| —              | `provider.name`            | hardcode `"claude"`       |

### Message-level mapping

| Provider field                | PAM field                 | Transform                                                       |
|-------------------------------|---------------------------|-----------------------------------------------------------------|
| `chat_messages[].uuid`        | `provider_message_id`     | direct                                                          |
| `chat_messages[].uuid`        | `id`                      | generate UUID or use original                                   |
| `chat_messages[].sender`      | `role`                    | `"human"`→`"user"`, `"assistant"`→`"assistant"`                 |
| `chat_messages[].text`        | `content.text`            | direct                                                          |
| `chat_messages[].content`     | `content.parts[]`         | if non-empty, map to multipart (see content type mapping below) |
| `chat_messages[].created_at`  | `created_at`              | direct (already ISO 8601)                                       |
| `chat_messages[].updated_at`  | `raw_metadata.updated_at` | preserve in raw_metadata                                        |
| `chat_messages[].attachments` | `attachments`             | map each to Attachment object                                   |
| `chat_messages[].files`       | `attachments`             | merge with attachments array                                    |
| —                             | `parent_id`               | `null` (Claude conversations are linear)                        |
| —                             | `children_ids`            | `[]` (Claude conversations are linear)                          |

### Content type mapping

Claude's `content[]` array contains structured blocks with a `type` field. Each type has specific fields:

| Provider `content[].type` | PAM `ContentPart.type` | Key fields                                     | Transform                                                                                                                 |
|---------------------------|------------------------|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| `text`                    | `text`                 | `text`, `citations[]`                          | Map `text` directly. Map `citations[]` to message-level `citations[]`.                                                    |
| `thinking`                | `text`                 | `thinking`, `summaries[]`, `cut_off`           | Map `thinking` to `text`. Set `is_thought: true` on the message. Preserve `summaries` and `cut_off` in `raw_metadata`.    |
| `tool_use`                | —                      | `name`, `input`, `id`                          | Map to message-level `tool_calls[]` with `name`, `input`, `id`.                                                           |
| `tool_result`             | —                      | `tool_use_id`, `name`, `content[]`, `is_error` | Map to a `tool` role message. Nested `content[]` may contain `knowledge` type with `title`, `url` (map to `citations[]`). |
| `token_budget`            | —                      | (no useful data)                               | Discard. Internal Claude token management.                                                                                |

**Common fields on all content parts** (preserve in `raw_metadata` if needed):

- `start_timestamp`, `stop_timestamp` — per-part timing
- `flags` — always observed as `null`

### Content type: `tool_use` detail

```json
{
  "type": "tool_use",
  "name": "web_search",
  "input": {
    "query": "..."
  },
  "id": null,
  "message": "Searching the web",
  "integration_name": null,
  "integration_icon_url": null,
  "is_mcp_app": null,
  "approval_options": null
}
```

Maps to PAM `tool_calls[]`:

```json
{
  "name": "web_search",
  "input": {
    "query": "..."
  },
  "id": null
}
```

### Content type: `tool_result` detail

```json
{
  "type": "tool_result",
  "tool_use_id": null,
  "name": "web_search",
  "content": [
    {
      "type": "knowledge",
      "title": "Page Title",
      "url": "https://example.com",
      "metadata": {
        "type": "webpage_metadata",
        "site_domain": "..."
      }
    }
  ],
  "is_error": false
}
```

Nested `content[].type: "knowledge"` items map to PAM `citations[]`:

```json
{
  "title": "Page Title",
  "url": "https://example.com"
}
```

### Memories mapping

`memories.json` contains a single-element array with:

| Provider field         | PAM target                     | Transform                                                                                                                                                                |
|------------------------|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `conversations_memory` | `memories[]` (type: `context`) | Parse string into individual memories. Single block of text — split heuristically or store as one memory.                                                                |
| `project_memories`     | `memories[]` (type: `project`) | Each key is a project UUID, value is structured text with sections (Purpose, Current state, Key learnings, Tools). Parse sections or store as single memory per project. |
| `account_uuid`         | `owner.id` or cross-reference  | Links to `users.json[].uuid`                                                                                                                                             |

### Critical notes

- **Field name**: `chat_messages`, NOT `messages`. Common source of bugs.
- **Sender values**: `"human"` and `"assistant"`, NOT `"user"` and `"assistant"`.
- **Content array**: `content[]` contains 5 observed types: `text`, `thinking`, `tool_use`, `tool_result`,
  `token_budget`. The `text` field at message level is a plain-text duplicate of the `content[]` text parts.
- **Linear structure**: Claude conversations do not branch. No DAG needed.
- **Attachments vs files**: Both `attachments[]` and `files[]` exist and may contain different data. Merge both into PAM
  `attachments[]`.
- **Summary field**: Conversations include a `summary` field (AI-generated overview). Not present in all conversations.
  Preserve in `raw_metadata`.
- **Projects and users**: `projects.json` and `users.json` provide additional context not directly mapped to PAM
  conversation schema but useful for `owner` and memory extraction.

---

## 3. Google (Gemini)

**Source:** Google Takeout (takeout.google.com → My Activity → Gemini Apps)
**Timestamp format:** ISO 8601
**Verified against:** Community-verified export structures and Google Takeout documentation

### Takeout format

**Path:** `Takeout/My Activity/Gemini Apps/MyActivity.json`
**Structure:** Single JSON array of activity events (one per interaction, NOT per conversation)

> **Important:** Select "My Activity → Gemini Apps" in Takeout, NOT a separate "Gemini" product.
> Selecting the wrong product produces empty or HTML-only exports. Change format from HTML to JSON
> via the "Multiple formats" button.

#### Activity event mapping

Each array element is a single prompt-response exchange:

| Provider field | PAM field                  | Transform                                                   |
|----------------|----------------------------|-------------------------------------------------------------|
| `titleUrl`     | `provider.conversation_id` | extract conversation ID from URL path                       |
| —              | `title`                    | extract from first user message per conversation, or `null` |
| `time`         | `created_at`               | direct (already ISO 8601)                                   |
| —              | `provider.name`            | hardcode `"gemini"`                                         |

#### Message mapping — variant A (`details` array)

```json
{
  "header": "Gemini",
  "title": "Used Gemini Apps",
  "titleUrl": "https://gemini.google.com/app/c/<conversation_id>",
  "time": "2024-02-17T22:05:10.123Z",
  "products": [
    "Gemini Apps"
  ],
  "details": [
    {
      "name": "Request",
      "value": "User prompt here"
    },
    {
      "name": "Response",
      "value": "Gemini response here"
    }
  ]
}
```

| Provider field    | PAM field      | Transform                                        |
|-------------------|----------------|--------------------------------------------------|
| `details[].value` | `content.text` | direct                                           |
| `details[].name`  | `role`         | `"Request"`→`"user"`, `"Response"`→`"assistant"` |

#### Message mapping — variant B (`userInteractions` array)

```json
{
  "header": "Gemini",
  "title": "Used Gemini Apps",
  "titleUrl": "https://gemini.google.com/app/c/<conversation_id>",
  "time": "2024-01-26T12:45:12.686Z",
  "products": [
    "Gemini Apps"
  ],
  "userInteractions": [
    {
      "userInteraction": {
        "endpoint": 2,
        "shown": false,
        "latencySeconds": 0.0,
        "request": "[{...}]",
        "response": "[{...}]"
      }
    }
  ]
}
```

| Provider field                                | PAM field      | Transform                                    |
|-----------------------------------------------|----------------|----------------------------------------------|
| `userInteractions[].userInteraction.request`  | `content.text` | parse JSON string, extract text              |
| `userInteractions[].userInteraction.response` | `content.text` | parse JSON string, extract text              |
| —                                             | `role`         | `request`→`"user"`, `response`→`"assistant"` |

### Critical notes

- **Takeout is an activity log, not a conversation archive.** Each entry is a single exchange, not a full thread.
  Importer must group entries by conversation ID (from `titleUrl`) and sort by `time` to reconstruct conversations.
- **Two Takeout variants:** Some exports use `details[{name, value}]`, others use
  `userInteractions[{request, response}]`.
  Importer must detect which variant is present per entry.
- **No titles in Takeout.** Generate from first user message.
- **Empty exports are common.** Selecting the wrong Takeout product, or having "Gemini App Activity" paused, produces
  empty or HTML-only exports.
- **Truncated responses.** Gemini Takeout frequently truncates or omits response text. Data loss is expected.
- **Author values:** Takeout uses `"Request"`/`"Response"` (in details) or implicit (in userInteractions).
  Neither uses `"assistant"` — normalization required.

---

## 4. Microsoft (Copilot)

**Source:** Microsoft Privacy Dashboard (https://account.microsoft.com/privacy/)
**Structure:** CSV files exported from Privacy Dashboard
**Timestamp format:** ISO 8601 with timezone offset, or `M/D/YYYY H:MM:SS +HH:MM`
**Verified against:** Real export from Feb 2026 (4 CSV files)

### Export files

The Privacy Dashboard export produces multiple CSV files:

| File                                         | Columns                                       | Description                                    |
|----------------------------------------------|-----------------------------------------------|------------------------------------------------|
| `copilot-activity-history.csv`               | `Conversation, Time, Author, Message`         | Main conversation history with full messages   |
| `copilot-chat-activity.csv`                  | `CreatedAt, MessageContent, Author, ChatName` | Chat-specific activity with conversation names |
| `copilot-in-Microsoft-365-apps-activity.csv` | `CreatedAt, MessageContent, Author, ChatName` | M365 app interactions (may be empty)           |
| `windows-apps-copilot-activity-history.csv`  | `Timestamp, ClientApp, Prompt`                | Windows app prompts only (no responses)        |

### CSV format A: `copilot-activity-history.csv` (primary)

| CSV Column     | PAM field                  | Transform                                       |
|----------------|----------------------------|-------------------------------------------------|
| `Conversation` | `title`                    | direct (conversation name/topic)                |
| `Time`         | `created_at`               | parse ISO 8601 (`2026-02-17T14:36:11`)          |
| `Author`       | `role`                     | `"user"`→`"user"`, `"AI"`→`"assistant"`         |
| `Message`      | `content.text`             | direct                                          |
| —              | `provider.name`            | hardcode `"copilot"`                            |
| —              | `provider.conversation_id` | generate from `Conversation` + session grouping |

### CSV format B: `copilot-chat-activity.csv`

| CSV Column       | PAM field       | Transform                                   |
|------------------|-----------------|---------------------------------------------|
| `ChatName`       | `title`         | direct                                      |
| `CreatedAt`      | `created_at`    | parse `M/D/YYYY H:MM:SS +HH:MM` to ISO 8601 |
| `Author`         | `role`          | `"user"`→`"user"`, other→`"assistant"`      |
| `MessageContent` | `content.text`  | direct                                      |
| —                | `provider.name` | hardcode `"copilot"`                        |

### Critical notes

- **CSV only verified format**: The Privacy Dashboard CSV is the only format verified with real data as of Feb 2026.
- **Two CSV column layouts**: `copilot-activity-history.csv` uses `Conversation/Time/Author/Message`, while
  `copilot-chat-activity.csv` uses `CreatedAt/MessageContent/Author/ChatName`. Importer must detect by header row.
- **Author values**: `"user"` and `"AI"` in activity-history format. `"user"` and assistant name in chat-activity
  format.
- **No message IDs**: CSV exports contain no message or conversation IDs. Generate UUIDs and group messages by
  `Conversation`/`ChatName` column + time proximity.
- **Timestamp inconsistency**: Different CSV files use different timestamp formats. Parse defensively.
- **Windows app CSV**: Only contains user prompts (`Prompt` column), no AI responses. Limited usefulness.

---

## 5. xAI (Grok)

**Source:** Data export via grok.com account settings → Download your data<br>
**Structure:** ZIP containing `ttl/30d/export_data/<user_uuid>/` with 3 JSON files.<br>
**Main file:** `prod-grok-backend.json` — dict with `conversations`, `projects`, `tasks`, `media_posts`  
**Companion files:** `prod-mc-auth-mgmt-api.json` (user profile + sessions), `prod-mc-billing.json` (credits balance)  
**Timestamp format:** ISO 8601 at conversation level, MongoDB BSON `{"$date":{"$numberLong":"<ms_epoch>"}}` at message
level

### Conversation-level mapping

Conversations are wrapped: each item is `{"conversation": {...}, "responses": [...]}`.

| Provider field                    | PAM field                         | Transform         |
|-----------------------------------|-----------------------------------|-------------------|
| `conversation.id`                 | `provider.conversation_id`        | direct            |
| `conversation.title`              | `title`                           | direct            |
| `conversation.create_time`        | `temporal.created_at`             | direct (ISO 8601) |
| `conversation.modify_time`        | `temporal.updated_at`             | direct (ISO 8601) |
| `conversation.user_id`            | `provider.account_id`             | direct            |
| `conversation.starred`            | `raw_metadata.starred`            | preserve          |
| `conversation.system_prompt_name` | `raw_metadata.system_prompt_name` | preserve          |
| —                                 | `provider.name`                   | hardcode `"grok"` |

### Message-level mapping

Each response is wrapped: `{"response": {...}, "share_link": {...}}`. The inner `response` object contains the message
data.

| Provider field                      | PAM field                            | Transform                                                                                |
|-------------------------------------|--------------------------------------|------------------------------------------------------------------------------------------|
| `response._id`                      | `provider_message_id`                | direct                                                                                   |
| `response._id`                      | `id`                                 | generate UUID or use original                                                            |
| `response.parent_response_id`       | `parent_id`                          | map provider ID → PAM ID                                                                 |
| —                                   | `children_ids`                       | reconstruct by inverting parent_response_id                                              |
| `response.sender`                   | `role`                               | see Role Normalization (case-insensitive + model names)                                  |
| `response.message`                  | `content.text`                       | direct                                                                                   |
| `response.create_time`              | `created_at`                         | BSON → `datetime.fromtimestamp(int(v["$date"]["$numberLong"])/1000, tz=UTC).isoformat()` |
| `response.model`                    | `model`                              | direct                                                                                   |
| `response.web_search_results`       | `raw_metadata.web_search_results`    | preserve                                                                                 |
| `response.cited_web_search_results` | `citations`                          | map each `{url, title, preview}` to Citation object                                      |
| `response.generated_image_urls`     | `attachments`                        | map each URL to Attachment with `type: "image"`                                          |
| `response.file_attachments`         | `attachments`                        | map each asset UUID; files in `prod-mc-asset-server/` directory                          |
| `response.thinking_trace`           | `raw_metadata.thinking_trace`        | preserve (contains XML-like `<xai:tool_usage_card>`)                                     |
| `response.thinking_start_time`      | `raw_metadata.thinking_start_time`   | BSON → ISO 8601                                                                          |
| `response.thinking_end_time`        | `raw_metadata.thinking_end_time`     | BSON → ISO 8601                                                                          |
| `response.agent_thinking_traces`    | `raw_metadata.agent_thinking_traces` | preserve                                                                                 |
| `response.steps`                    | `raw_metadata.steps`                 | preserve (tool use chain with tagged_text, tool_usage_results)                           |
| `response.query`                    | `raw_metadata.query`                 | preserve (image generation prompt)                                                       |
| `response.query_type`               | `raw_metadata.query_type`            | preserve (`"imagine"` for image generation)                                              |
| `response.xpost_ids`                | `raw_metadata.xpost_ids`             | preserve (X/Twitter post references)                                                     |
| `response.webpage_urls`             | `raw_metadata.webpage_urls`          | preserve                                                                                 |
| `response.card_attachments_json`    | `raw_metadata.card_attachments_json` | preserve                                                                                 |
| `response.error`                    | `raw_metadata.error`                 | preserve (e.g., `"Failed to respond."`)                                                  |
| `response.metadata`                 | `raw_metadata.grok_metadata`         | preserve (contains `ui_layout`, `llm_info`, `request_metadata`)                          |

### Additional data sources

| Source                                | Content                                                                                 | PAM mapping                                             |
|---------------------------------------|-----------------------------------------------------------------------------------------|---------------------------------------------------------|
| `projects[]`                          | Custom workspaces with `custom_personality`, `preferred_model`, `conversation_starters` | Could generate `instruction` or `project` type memories |
| `media_posts[]`                       | Generated images/videos with `original_prompt`, `media_type`, `link`                    | Standalone attachments, no conversation context         |
| `prod-mc-auth-mgmt-api.json` → `user` | Profile: `email`, `givenName`, `familyName`, `birthDate`                                | Could generate `identity` type memories                 |
| `prod-mc-asset-server/` directory     | Uploaded files (code, images, PDFs, etc.) referenced by asset UUID                      | Referenced by `file_attachments` in responses           |

### Critical notes

- **Wrapper nesting**: Every conversation is `{conversation, responses}` and every response is `{response, share_link}`.
  Must unwrap twice.
- **Sender inconsistency**: Four distinct values observed: `"human"`, `"assistant"`, `"ASSISTANT"` (uppercase), and
  `"grok-3"` (model name as sender). Normalization MUST be case-insensitive and treat any non-`"human"` value as
  `"assistant"`.
- **Mixed timestamp formats**: Conversation-level uses ISO 8601, message-level uses BSON
  `{"$date":{"$numberLong":"<milliseconds_epoch>"}}`. Two different parsers needed for the same file.
- **DAG structure**: `parent_response_id` is present on 90% of messages (3075 of 3421). Supports branching conversations
  like ChatGPT. `children_ids` must be reconstructed by inverting parent references.
- **Empty messages**: 14 responses have `message: ""` (empty string, not null). These are typically image generation
  responses where the content is in `generated_image_urls`.
- **Steps = tool use chain**: `steps[]` contains structured tool execution with `tag_order`, `tagged_text`,
  `web_search_results`, `tool_usage_results`. This is Grok's equivalent of function calling.
- **Thinking traces**: Two separate mechanisms — `thinking_trace` (inline string with XML-like tags) and
  `agent_thinking_traces[]` (array of `{agent_id, thinking_trace}`). Both may be present on the same response.
- **5 model variants observed**: `grok-3`, `grok-4`, `grok-4-auto`, `grok-4-mini-thinking-tahoe`,
  `grok-4-1-non-thinking-w-tool`.
- **Asset files**: Uploads are stored as UUID-named directories in `prod-mc-asset-server/`, each containing a `content`
  file with no extension. Majority are source code (55% Python), not binary files. Use `file` command or content
  inspection to determine type.
- **X/Twitter integration**: `xpost_ids` field links to X posts. Unique to Grok — no other provider has social media
  cross-references.

---

## 6. Role Normalization Reference

| Provider  | Provider value        | PAM normalized value |
|-----------|-----------------------|----------------------|
| OpenAI    | `user`                | `user`               |
| OpenAI    | `assistant`           | `assistant`          |
| OpenAI    | `system`              | `system`             |
| OpenAI    | `tool`                | `tool`               |
| Anthropic | `human`               | `user`               |
| Anthropic | `assistant`           | `assistant`          |
| Google    | `Request` (Takeout)   | `user`               |
| Google    | `Response` (Takeout)  | `assistant`          |
| Microsoft | `user` (CSV)          | `user`               |
| Microsoft | `AI` (CSV)            | `assistant`          |
| xAI       | `human`               | `user`               |
| xAI       | `assistant`           | `assistant`          |
| xAI       | `ASSISTANT`           | `assistant`          |
| xAI       | `grok-3` (model name) | `assistant`          |
| xAI       | any non-`human` value | `assistant`          |

---

## 7. Timestamp Normalization Reference

| Provider           | Format                                  | Transform                                                                         |
|--------------------|-----------------------------------------|-----------------------------------------------------------------------------------|
| OpenAI             | Unix epoch (float)                      | `datetime.fromtimestamp(v, tz=UTC).isoformat()`                                   |
| Anthropic          | ISO 8601                                | direct                                                                            |
| Google (Takeout)   | ISO 8601                                | direct                                                                            |
| Microsoft (CSV)    | locale date                             | parse with `dateutil`                                                             |
| xAI (conversation) | ISO 8601                                | direct                                                                            |
| xAI (message)      | BSON `{"$date":{"$numberLong":"<ms>"}}` | `datetime.fromtimestamp(int(v["$date"]["$numberLong"])/1000, tz=UTC).isoformat()` |

---

## 8. Importer Versioning

Providers change export formats without notice. Every importer MUST be versioned:

```json
{
  "import_metadata": {
    "importer": "gines/0.5.0",
    "importer_version": "openai-importer/2025.01",
    "imported_at": "2026-02-15T22:00:00Z",
    "source_file": "conversations.json",
    "source_checksum": "sha256:abc123..."
  }
}
```

When a provider changes their format:

1. Create a new importer version (e.g., `openai-importer/2026.01`)
2. Keep the old importer for re-processing older exports
3. Auto-detect format version when possible (schema differences, field presence)

---

## 9. Detection Heuristics

How to auto-detect which provider format a file uses:

```python
def detect_provider(data):
    if isinstance(data, list):
        sample = data[0] if data else {}
        if "mapping" in sample:
            return "chatgpt"
        if "chat_messages" in sample:
            return "claude"
        if "header" in sample and ("details" in sample or "userInteractions" in sample):
            return "gemini"
    if isinstance(data, dict):
        if "conversations" in data and isinstance(data["conversations"], list):
            sample = data["conversations"][0] if data["conversations"] else {}
            if "conversation" in sample and "responses" in sample:
                return "grok"
        # Note: Copilot consumer export is CSV, not JSON.
        # Detection for Copilot CSV must be done by file extension/header, not JSON structure.
    return "unknown"
```
