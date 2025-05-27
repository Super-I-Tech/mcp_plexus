# mcp_plexus/sessions/session_manager.py
import logging
from typing import Optional, Tuple
from uuid import uuid4

from .session_data import SessionData
from .session_store import AbstractSessionStore

logger = logging.getLogger(__name__)


class PlexusSessionManager:
    """Manages session lifecycle including creation, retrieval, persistence, and deletion."""
    
    def __init__(self, store: AbstractSessionStore):
        if not isinstance(store, AbstractSessionStore):
            raise TypeError("PlexusSessionManager requires an instance of AbstractSessionStore.")
        self.store = store
        logger.info(f"PlexusSessionManager initialized with store: {type(store).__name__}")

    def _generate_new_mcp_session_id(self) -> str:
        """Generate a unique session identifier using UUID4."""
        new_id = uuid4().hex
        logger.debug(f"Generated new MCP session ID: {new_id}")
        return new_id

    def _construct_session_key(self, entity_id: str, mcp_session_id: str) -> str:
        """
        Construct a session key for storage operations.
        
        Uses the store's specific key construction method if available,
        otherwise falls back to a generic format.
        """
        if not entity_id or not mcp_session_id:
            logger.error("_construct_session_key: entity_id and mcp_session_id must be non-empty.")
            raise ValueError("entity_id and mcp_session_id are required to construct a session key.")
        
        if hasattr(self.store, "_construct_redis_key"):  
            key = self.store._construct_redis_key(entity_id, mcp_session_id) # type: ignore
            logger.debug(f"Constructed session key using store's method: '{key}' for E:{entity_id}, S:{mcp_session_id}")
            return key
        
        generic_key = f"plexus:session:{entity_id}:{mcp_session_id}"
        logger.debug(f"Constructed generic session key: '{generic_key}' for E:{entity_id}, S:{mcp_session_id}")
        return generic_key

    async def get_session(
        self, entity_id: str, client_provided_mcp_session_id: Optional[str]
    ) -> Tuple[SessionData, bool]:
        """
        Retrieve or create a session for the given entity.
        
        Returns a tuple of (SessionData, is_newly_created).
        If client provides a session ID, attempts to load existing session.
        If no session ID provided or session not found, creates a new one.
        """
        is_newly_created_in_store = False 
        session_data: Optional[SessionData] = None
        session_id_to_use: str

        if client_provided_mcp_session_id:
            session_id_to_use = client_provided_mcp_session_id
            session_key = self._construct_session_key(entity_id, session_id_to_use)
            logger.debug(
                f"get_session: Attempting to load session for entity '{entity_id}' "
                f"with client-provided ID '{session_id_to_use}' (key: '{session_key}')"
            )
            session_data = await self.store.load_session(session_key)

            if session_data:
                # Verify entity ID matches to prevent session hijacking
                if session_data.entity_id != entity_id:
                    logger.warning(
                        f"get_session: Loaded session for ID '{session_id_to_use}' but its entity_id "
                        f"'{session_data.entity_id}' mismatches requested entity_id '{entity_id}'. "
                        f"Creating new session for security."
                    )
                    session_data = SessionData( 
                        mcp_session_id=session_id_to_use,
                        entity_id=entity_id,
                    )
                    is_newly_created_in_store = True 
                else:
                    logger.info(
                        f"get_session: Existing session loaded for entity '{entity_id}', "
                        f"Mcp-Session-Id: {session_id_to_use}"
                    )
                    session_data.touch() 
            else: 
                logger.info(
                    f"get_session: No session found for entity '{entity_id}' with "
                    f"client-provided ID '{session_id_to_use}'. Creating new session."
                )
                session_data = SessionData(
                    mcp_session_id=session_id_to_use,
                    entity_id=entity_id,
                )
                is_newly_created_in_store = True 
        
        else: 
            # No client session ID provided - generate new session and auto-save
            session_id_to_use = self._generate_new_mcp_session_id()
            logger.info(
                f"get_session: Client did not provide Mcp-Session-Id. Generated new: "
                f"{session_id_to_use} for entity '{entity_id}'. Auto-saving session."
            )
            session_data = SessionData(
                mcp_session_id=session_id_to_use,
                entity_id=entity_id,
            )
            await self.save_session(session_data) 
            logger.info(f"get_session: Auto-saved new session for Mcp-Session-Id: {session_data.mcp_session_id}")
            is_newly_created_in_store = True 

        # Fallback safety check
        if not session_data: 
            logger.error("get_session: session_data is None - creating fallback session")
            final_session_id = client_provided_mcp_session_id or self._generate_new_mcp_session_id()
            session_data = SessionData(mcp_session_id=final_session_id, entity_id=entity_id)
            is_newly_created_in_store = True 

        return session_data, is_newly_created_in_store

    async def save_session(self, session_data: SessionData) -> None:
        """
        Persist session data to the store.
        
        Includes safety checks to prevent accidental data loss when clearing
        internal data while existing CSRF/PKCE data exists in storage.
        """
        if not isinstance(session_data, SessionData):
            logger.error(f"save_session: Attempted to save non-SessionData object: {type(session_data)}")
            raise TypeError("session_data must be an instance of SessionData.")

        session_data.touch()  
        
        logger.info(
            f"save_session: Saving session - McpSessID: '{session_data.mcp_session_id}', "
            f"EntityID: '{session_data.entity_id}', PersistentUserID: '{session_data.persistent_user_id}'"
        )
        
        is_clearing_internal_data = not session_data.plexus_internal_data
        has_oauth_tokens_to_save = bool(session_data.oauth_tokens)

        # Safety check: prevent accidental clearing of CSRF/PKCE data
        if is_clearing_internal_data and not has_oauth_tokens_to_save:
            try:
                key_to_check = self._construct_session_key(session_data.entity_id, session_data.mcp_session_id)
                existing_session_in_store = await self.store.load_session(key_to_check)
                
                if existing_session_in_store and existing_session_in_store.plexus_internal_data:
                    logger.warning(
                        f"save_session: Skipping save for McpSessID '{session_data.mcp_session_id}' "
                        f"to prevent loss of existing internal data (CSRF/PKCE protection)"
                    )
                    return  
            except Exception as e:
                logger.error(
                    f"save_session: Error during safety check for {session_data.mcp_session_id}: {e}. "
                    f"Proceeding with save.", 
                    exc_info=True
                )
        
        try:
            await self.store.save_session(session_data)
            logger.info(
                f"save_session: Successfully saved session for McpSessID: '{session_data.mcp_session_id}'"
            )
        except Exception as e:
            logger.error(
                f"save_session: Failed to save session for McpSessID '{session_data.mcp_session_id}': {e}", 
                exc_info=True
            )
            raise

    async def delete_session(self, entity_id: str, mcp_session_id: str) -> None:
        """Delete a session from the store."""
        session_key = self._construct_session_key(entity_id, mcp_session_id)
        logger.debug(
            f"delete_session: Deleting session for entity '{entity_id}' "
            f"with key '{session_key}' (ID: {mcp_session_id})"
        )
        try:
            await self.store.delete_session(session_key)
            logger.info(
                f"delete_session: Session deleted for entity '{entity_id}', "
                f"Mcp-Session-Id: {mcp_session_id}"
            )
        except Exception as e:
            logger.error(
                f"delete_session: Error deleting session {mcp_session_id}: {e}", 
                exc_info=True
            )
            raise