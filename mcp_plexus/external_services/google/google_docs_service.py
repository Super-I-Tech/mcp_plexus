# mcp_plexus/external_services/google_docs_service.py
import httpx
import asyncio
import logging
import json
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

DOCS_API_BASE_URL = "https://docs.googleapis.com/v1"
DRIVE_API_BASE_URL = "https://www.googleapis.com/drive/v3"

class GoogleDocsService:
    """Service for interacting with Google Docs and Drive APIs."""
    
    def __init__(self, client: httpx.AsyncClient):
        """Initialize the service with an authenticated HTTP client."""
        self.client = client
        logger.info("GoogleDocsService initialized with authenticated httpx.AsyncClient.")

    async def _request(
        self,
        method: str,
        url: str,
        json_payload: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make an authenticated request to Google APIs with comprehensive error handling.
        
        Returns the JSON response for successful requests, or raises an exception for errors.
        """
        try:
            logger.debug(f"Google API Request: {method} {url} | Params: {params} | JSON: {json_payload is not None}")
            
            response = await self.client.request(method, url, json=json_payload, params=params)
            
            request_details = f"Request: {response.request.method} {response.request.url}"
            if json_payload:
                request_details += f" | Body: {json.dumps(json_payload)}"
            logger.debug(request_details)
            
            if 200 <= response.status_code < 300:
                # Handle successful responses with no content
                if response.status_code == 204:
                    logger.debug(f"Google API Response: {method} {url} -> {response.status_code} No Content")
                    return {"status_code": response.status_code} 
                
                if response.content:
                    try:
                        json_response = response.json()
                        # Truncate long responses for logging to avoid log spam
                        log_body_preview = str(json_response)
                        if len(log_body_preview) > 300:
                            log_body_preview = log_body_preview[:300] + "..."
                        logger.debug(f"Google API Response: {method} {url} -> {response.status_code} | Body Preview: {log_body_preview}")
                        return json_response
                    except json.JSONDecodeError:
                        logger.error(f"Google API Response: {method} {url} -> {response.status_code} | Failed to decode JSON. Body: {response.text}")
                        raise Exception(f"Google API Error: Failed to decode JSON response. Status: {response.status_code}")
                else:
                    logger.warning(f"Google API Response: {method} {url} -> {response.status_code} success with empty body.")
                    return {"status_code": response.status_code}
            else:
                # Extract error message from response for better error reporting
                error_text = "Unknown error"
                error_details_for_log = response.text
                if response.content:
                    try:
                        error_details_parsed = response.json()
                        error_text = error_details_parsed.get('error', {}).get('message', response.text)
                        error_details_for_log = json.dumps(error_details_parsed)
                    except json.JSONDecodeError:
                        error_text = response.text
                logger.error(
                    f"Google API HTTP Error: {response.request.method} {response.request.url} - Status {response.status_code} - Response Body: {error_details_for_log}"
                )
                raise httpx.HTTPStatusError(
                    message=f"Google API Error ({response.status_code}): {error_text}", 
                    request=response.request, 
                    response=response
                )

        except httpx.HTTPStatusError as e:
            # Avoid double logging by checking if we already logged this error
            if not hasattr(e, '_already_logged_by_plexus'):
                error_text_rethrow = "Unknown error from HTTPStatusError"
                if e.response and e.response.content:
                    try:
                        err_json = e.response.json()
                        error_text_rethrow = err_json.get('error', {}).get('message', e.response.text)
                    except:
                        error_text_rethrow = e.response.text
                logger.error(f"Google API RETHROWN HTTPStatusError: {e.request.method} {e.request.url} - Status {e.response.status_code if e.response else 'N/A'} - Error Text: {error_text_rethrow}")
                e._already_logged_by_plexus = True
            # Re-wrap for consistent exception type from service
            raise Exception(f"Google API Error: {str(e)}") from e
        except httpx.RequestError as e:
            logger.error(f"Google API RequestError: {e.request.method} {e.request.url} - Error: {e}")
            raise Exception(f"Google API Connection/Request Error: {str(e)}") from e
        except Exception as e: 
            logger.error(f"Unexpected error in GoogleDocsService._request for {method} {url}: {e}", exc_info=True)
            raise

    async def create_document(
        self, 
        title: str = "Default New Document", 
        initial_content: Optional[str] = None, 
        folder_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a new Google Document using the Drive API.
        
        Optionally adds initial content and places the document in a specific folder.
        """
        doc_metadata = {'name': title, 'mimeType': 'application/vnd.google-apps.document'}
        if folder_id:
            doc_metadata['parents'] = [folder_id]

        drive_url = f"{DRIVE_API_BASE_URL}/files"
        drive_params = {'fields': 'id,name,webViewLink,mimeType,parents'}
        
        created_file_info = await self._request("POST", drive_url, json_payload=doc_metadata, params=drive_params)
        document_id = created_file_info.get('id')
        
        if not document_id:
            logger.error(f"Failed to create document with title '{title}'. Drive API Response: {created_file_info}")
            raise Exception(f"Failed to create document, no ID returned by Drive API.")

        logger.info(f"Created Google document via Drive API with ID: {document_id}, Name: {created_file_info.get('name')}")
        
        doc_info = {
            "documentId": document_id, 
            "title": created_file_info.get('name'),
            "webViewLink": created_file_info.get('webViewLink'),
            "parents": created_file_info.get('parents'),
            "mimeType": created_file_info.get('mimeType')
        }

        # Add initial content if provided
        if initial_content:
            logger.info(f"Adding initial content to document {document_id}.")
            insert_request = [{"insertText": {"location": {"index": 1}, "text": initial_content}}]
            try:
                await self.edit_document(document_id, insert_request)
                doc_info["initial_content_status"] = "successfully_inserted"
            except Exception as e_insert:
                logger.error(f"Failed to insert initial content into document {document_id}: {e_insert}")
                doc_info["initial_content_status"] = f"failed_to_insert: {str(e_insert)}"
        
        return doc_info

    async def share_document_with_org(self, document_id: str, domain: str, role: str = "writer") -> Dict[str, Any]:
        """Share a document with an entire organization domain."""
        url = f"{DRIVE_API_BASE_URL}/files/{document_id}/permissions"
        permission_body = {'type': 'domain', 'role': role, 'domain': domain}
        params = {'sendNotificationEmail': 'false', 'fields': 'id'}
        result = await self._request("POST", url, json_payload=permission_body, params=params)
        logger.info(f"Shared document {document_id} with organization domain '{domain}' as '{role}'. Permission ID: {result.get('id')}")
        return result

    async def edit_document(self, document_id: str, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply a batch of edit operations to a document using the Docs API."""
        if not requests:
            logger.info(f"No edit requests provided for document {document_id}. Skipping batchUpdate.")
            return {"documentId": document_id, "replies": [], "message": "No edit operations performed."}
        
        url = f"{DOCS_API_BASE_URL}/documents/{document_id}:batchUpdate"
        body = {'requests': requests}
        result = await self._request("POST", url, json_payload=body)
        logger.info(f"Document {document_id} updated via batchUpdate ({len(requests)} requests).")
        return result

    async def read_document(self, document_id: str) -> Dict[str, Any]:
        """Retrieve the full document structure including content and metadata."""
        url = f"{DOCS_API_BASE_URL}/documents/{document_id}"
        params = {
            'fields': 'documentId,title,body(content(paragraph(elements(textRun(content,textStyle))),startIndex,endIndex)),revisionId'
        }
        doc = await self._request("GET", url, params=params)
        logger.info(f"Read document {document_id}")
        return doc

    def extract_text(self, doc: Dict[str, Any]) -> str:
        """
        Extract plain text content from a Google Docs document structure.
        
        Preserves paragraph breaks and handles empty lines appropriately.
        """
        text_segments = []
        body_content = doc.get('body', {}).get('content', [])
        
        for structural_element in body_content:
            if 'paragraph' in structural_element:
                paragraph = structural_element['paragraph']
                for element in paragraph.get('elements', []):
                    if 'textRun' in element:
                        text_run = element['textRun']
                        content = text_run.get('content', '')
                        text_segments.append(content)
        
        full_text = "".join(text_segments)
        # Preserve empty lines while removing trailing newlines from paragraphs
        paragraphs = [p.rstrip('\n') for p in full_text.split('\n') if p or p == ""]
        final_text = "\n".join(paragraphs)
        
        return final_text

    async def read_document_text(self, document_id: str) -> str:
        """Convenience method to read a document and return only its text content."""
        doc = await self.read_document(document_id)
        return self.extract_text(doc)

    async def rewrite_document(self, document_id: str, final_text: str) -> Dict[str, Any]:
        """
        Replace the entire content of a document with new text.
        
        This operation deletes all existing content and inserts the new text.
        """
        logger.info(f"Attempting to rewrite document ID: {document_id} with text of length {len(final_text)}")
        doc_before_rewrite = await self.read_document(document_id)
        current_content_elements = doc_before_rewrite.get("body", {}).get("content", [])
        
        requests = []
        doc_content_end_index = 1
        
        # Determine the end index of existing content
        if current_content_elements:
            if isinstance(current_content_elements[-1], dict) and current_content_elements[-1].get("endIndex"):
                doc_content_end_index = current_content_elements[-1].get("endIndex", 1)
            else:
                logger.warning(f"Last element in content of doc {document_id} is not a dict or has no endIndex. Elements: {current_content_elements}")

        logger.debug(f"Document {document_id} original total endIndex (exclusive): {doc_content_end_index}")

        # Delete existing content if there is any to delete
        if doc_content_end_index > 1:
            # Delete all content except the final implicit newline
            end_index_for_delete = doc_content_end_index - 1
            if end_index_for_delete >= 1:
                requests.append({
                    "deleteContentRange": {
                        "range": { 
                            "startIndex": 1, 
                            "endIndex": end_index_for_delete
                        }
                    }
                })
                logger.debug(f"Prepared deleteContentRange: startIndex=1, endIndex={end_index_for_delete}")
            else:
                logger.debug("No content to delete (calculated endIndex for delete range is < 1).")
        else:
            logger.debug("No existing content to delete based on endIndex (document is effectively empty or just initial newline).")

        # Insert new content if provided
        if final_text: 
            requests.append({
                "insertText": {
                    "location": {"index": 1},
                    "text": final_text
                }
            })
            logger.debug(f"Prepared insertText at index 1 for text of length {len(final_text)}")
        
        if not requests:
            logger.info(f"Document {document_id} rewrite: No change operations determined (e.g., empty doc and empty final_text).")
            return {"documentId": document_id, "replies": [], "message": "No effective changes made to document."}

        logger.info(f"Rewriting document {document_id} with {len(requests)} API operations.")
        return await self.edit_document(document_id, requests)

    async def read_comments(self, document_id: str) -> List[Dict[str, Any]]:
        """Retrieve all comments and their replies for a document."""
        url = f"{DRIVE_API_BASE_URL}/files/{document_id}/comments"
        params = {
            'fields': "comments(id,content,author(displayName,emailAddress,photoLink),createdTime,modifiedTime,resolved,replies(id,content,author(displayName,emailAddress,photoLink),createdTime,modifiedTime))"
        }
        response = await self._request("GET", url, params=params)
        comments = response.get('comments', [])
        logger.info(f"Retrieved {len(comments)} comments for document {document_id}")
        return comments

    async def reply_comment(self, document_id: str, comment_id: str, reply_content: str) -> Dict[str, Any]:
        """Add a reply to an existing comment on a document."""
        url = f"{DRIVE_API_BASE_URL}/files/{document_id}/comments/{comment_id}/replies"
        body = {'content': reply_content}
        params = {'fields': "id,content,author(displayName,emailAddress,photoLink),createdTime,modifiedTime"}
        reply = await self._request("POST", url, json_payload=body, params=params)
        logger.info(f"Posted reply to comment {comment_id} in document {document_id}. Reply ID: {reply.get('id')}")
        return reply

    async def create_comment(self, document_id: str, content: str) -> Dict[str, Any]:
        """Create a new comment on a document."""
        url = f"{DRIVE_API_BASE_URL}/files/{document_id}/comments"
        body = {"content": content}
        params = {'fields': "id,content,author(displayName,emailAddress,photoLink),createdTime,modifiedTime"}
        comment = await self._request("POST", url, json_payload=body, params=params)
        logger.info(f"Created comment with ID: {comment.get('id')} on document {document_id}")
        return comment

    async def delete_reply(self, document_id: str, comment_id: str, reply_id: str) -> Dict[str, Any]:
        """Delete a specific reply from a comment."""
        url = f"{DRIVE_API_BASE_URL}/files/{document_id}/comments/{comment_id}/replies/{reply_id}"
        result = await self._request("DELETE", url) 
        logger.info(f"Deleted reply {reply_id} for comment {comment_id} in document {document_id}")
        return result