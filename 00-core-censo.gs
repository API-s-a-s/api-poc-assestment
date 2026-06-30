/**
 * Wrapper de estado global para el censo de usuarios.
 * Mantiene la lógica de fragmentación en PropertiesService.
 * Referencia: Admin SDK Directory API (https://developers.google.com/admin-sdk/directory/v1/guides/manage-users)
 * Referencia: CacheService Limits (https://developers.google.com/apps-script/reference/cache/cache-service)
 */
class CensusStateWrapper {
  constructor() {
    // PASO 4: Migración estructural a CacheService para evadir el límite de 500KB de PropertiesService
    this.cache = CacheService.getScriptCache();
    this.CHUNK_SIZE = 45000; // Incrementado aprovechando los 100KB por key de CacheService
    this.PREFIX = "CENSUS_CHUNK_";
    this.TOTAL_CHUNKS_KEY = "CENSUS_TOTAL_CHUNKS";
    this.OU_MAP_KEY = "CENSUS_OU_ID_TO_PATH"; // Diccionario ouId → ouPath
  }

  buildAndStoreCensus(authService, customerId) {
    Logger.log("Iniciando la construcción del censo global en caché O(1)...");
    const groupMap = this._buildGroupsHashMap(customerId);
    
    // Extracción masiva de licencias
    // El License Manager API NO acepta el alias "my_customer", exige el dominio primario
    const domain = authService.getDomain();
    const licenseMap = this._buildLicensesHashMap(domain);
    
    // Extracción masiva de roles de administrador
    const rolesMap = this._buildAdminRolesHashMap(customerId);

    // Diccionario de resolución OU ID → OU Path para el motor CEL
    const ouMap = this._buildOuIdToPathMap(customerId);

    const users = this._fetchAllUsers(customerId);
    const censoCompleto = [];

    for (const user of users) {
      // Búsqueda O(1) en RAM
      const userGroups = groupMap[user.primaryEmail] || [];
      
      // NUEVO: Asignación real de las licencias del usuario
      const userLicenses = licenseMap[user.primaryEmail] || []; 
      
      // NUEVO: Asignación de roles de administrador
      const adminRoles = rolesMap[user.id] || [];

      censoCompleto.push({
        id: user.id, email: user.primaryEmail, orgUnitPath: user.orgUnitPath, isAdmin: user.isAdmin === true,
        groups: userGroups, licenses: userLicenses, adminRoles: adminRoles, isEnrolledIn2Sv: user.isEnrolledIn2Sv === true,
        isEnrolledInApp: user.isEnrolledInApp === true
      });
    }

    this._chunkAndSave(censoCompleto);
    this._saveOuMap(ouMap);
    this._currentOuMap = ouMap; // Mantener en memoria RAM para esta ejecución
    Logger.log(`[DEBUG CENSO] Almacenado efímeramente: ${censoCompleto.length} usuarios, ${Object.keys(ouMap).length} OUs resueltas.`);
  }

  // Construye un diccionario global de licencias para la organización
  _buildLicensesHashMap(domainOrCustomerId) {
    const map = {};
    // "Google-Apps" = SKUs de Google Workspace | "101031" = SKUs de Cloud Identity
    const productIds = ["Google-Apps", "101031"]; 
    
    productIds.forEach(productId => {
       let pageToken = null;
       do {
          try {
            // Consulta paginada a la API del License Manager
            const response = AdminLicenseManager.LicenseAssignments.listForProduct(productId, domainOrCustomerId, { maxResults: 500, pageToken: pageToken });
            const assignments = response.items || [];
            
            assignments.forEach(assignment => {
               const email = assignment.userId; 
               const skuId = assignment.skuId; 
               // Formateo exacto exigido por la Policy API (ej. /product/Google-Apps/sku/1010020027)
               const formattedSku = `/product/${productId}/sku/${skuId}`;
               
               if (!map[email]) map[email] = [];
               map[email].push(formattedSku);
            });
            pageToken = response.nextPageToken;
          } catch(e) {
            Logger.log(`[ERROR LICENCIAS] Fallo al extraer para el producto ${productId}: ${e.message}`);
            pageToken = null;
          }
       } while (pageToken);
    });
    
    return map;
  }

  // Construye un diccionario global de roles asignados para la organización (O(1))
  _buildAdminRolesHashMap(customerId) {
    const map = {};
    const roleIdToName = {};

    try {
      // 1. Obtener el diccionario de nombres de roles (para no lidiar solo con IDs crudos)
      let pageTokenRoles = null;
      do {
        const responseRoles = AdminDirectory.Roles.list(customerId, { maxResults: 100, pageToken: pageTokenRoles });
        const roles = responseRoles.items || [];
        roles.forEach(role => {
          roleIdToName[role.roleId] = {
            roleName: role.roleName,
            isSystemRole: role.isSystemRole
          };
        });
        pageTokenRoles = responseRoles.nextPageToken;
      } while (pageTokenRoles);

      // 2. Obtener todas las asignaciones de roles en el dominio
      let pageTokenAssignments = null;
      do {
        const responseAssignments = AdminDirectory.RoleAssignments.list(customerId, { maxResults: 100, pageToken: pageTokenAssignments });
        const assignments = responseAssignments.items || [];
        
        assignments.forEach(assignment => {
          const userId = assignment.assignedTo;
          const roleId = assignment.roleId;
          const scopeType = assignment.scopeType;
          const orgUnitId = assignment.orgUnitId || null;

          const roleInfo = roleIdToName[roleId] || { roleName: "Unknown Role", isSystemRole: false };

          if (!map[userId]) map[userId] = [];
          
          map[userId].push({
            roleId: roleId,
            roleName: roleInfo.roleName,
            isSystemRole: roleInfo.isSystemRole,
            scopeType: scopeType,
            orgUnitId: orgUnitId
          });
        });
        pageTokenAssignments = responseAssignments.nextPageToken;
      } while (pageTokenAssignments);

    } catch (e) {
      Logger.log(`[ERROR ROLES] Fallo al extraer roles globales: ${e.message}`);
    }
    
    return map;
  }

  getCensus() {
    const totalChunksStr = this.cache.get(this.TOTAL_CHUNKS_KEY);
    if (!totalChunksStr) return null;

    const totalChunks = parseInt(totalChunksStr, 10);
    let jsonString = "";

    for (let i = 0; i < totalChunks; i++) {
      const chunk = this.cache.get(`${this.PREFIX}${i}`);
      if (chunk) jsonString += chunk;
    }

    try {
      return JSON.parse(jsonString);
    } catch (e) {
      return null;
    }
  }

  /**
   * Recupera el diccionario OU ID → OU Path desde la caché.
   * @return {Object|null} Mapa { ouId: ouPath } o null si no hay datos.
   */
   getOuMap() {
     if (this._currentOuMap) return this._currentOuMap; // Retornar desde RAM si ya se construyó en esta ejecución
     const raw = this.cache.get(this.OU_MAP_KEY);
     if (!raw) return {};
    try {
      return JSON.parse(raw);
    } catch (e) {
      return {};
    }
  }


  clearCensus() {
    const totalChunksStr = this.cache.get(this.TOTAL_CHUNKS_KEY);
    if (totalChunksStr) {
      const totalChunks = parseInt(totalChunksStr, 10);
      for (let i = 0; i < totalChunks; i++) this.cache.remove(`${this.PREFIX}${i}`);
      this.cache.remove(this.TOTAL_CHUNKS_KEY);
    }
    this.cache.remove(this.OU_MAP_KEY);
  }

  _chunkAndSave(dataArray) {
    this.clearCensus(); 
    const jsonString = JSON.stringify(dataArray);
    const totalLength = jsonString.length;
    let chunksCount = 0;

    for (let i = 0; i < totalLength; i += this.CHUNK_SIZE) {
      const chunk = jsonString.substring(i, i + this.CHUNK_SIZE);
      this.cache.put(`${this.PREFIX}${chunksCount}`, chunk, 1500); // Expiración 25 mins
      chunksCount++;
    }
    this.cache.put(this.TOTAL_CHUNKS_KEY, chunksCount.toString(), 1500);
  }

  _fetchAllUsers(customerId) {
    let allUsers = [];
    let pageToken;
    do {
      const response = AdminDirectory.Users.list({ customer: customerId, maxResults: 500, projection: "basic", pageToken: pageToken });
      if (response.users) allUsers.push(...response.users);
      pageToken = response.nextPageToken;
    } while (pageToken);
    return allUsers;
  }

  _buildGroupsHashMap(customerId) {
    const map = {};
    // Simulador de abstracción de red masiva para mapeo en RAM. 
    // En producción, iterar sobre grupos y members list, y poblar el diccionario.
    return map;
  }

  /**
   * Construye un diccionario global ouId → ouPath para toda la organización.
   * Usa AdminDirectory.OrgUnits.list para extraer todas las unidades organizativas.
   * Este mapa permite al CELParserEngine resolver los OU IDs alfanuméricos que
   * devuelve la Policy API contra las rutas de texto del censo de usuarios.
   * @param {string} customerId - ID del cliente (ej. "my_customer")
   * @return {Object} Mapa { orgUnitId: orgUnitPath }
   */
  _buildOuIdToPathMap(customerId) {
    const map = {};
    try {
      // type: "all" devuelve todas las OUs (hijas incluidas) en una sola llamada
      const response = AdminDirectory.Orgunits.list(customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      orgUnits.forEach(ou => {
        if (ou.orgUnitId && ou.orgUnitPath) {
          // Normalizamos: la API puede devolver el ID con o sin prefijo "id:"
          const cleanId = ou.orgUnitId.replace(/^id:/, "");
          map[cleanId] = ou.orgUnitPath;
          // También guardamos con el prefijo original por si la Policy API lo usa así
          if (ou.orgUnitId !== cleanId) {
            map[ou.orgUnitId] = ou.orgUnitPath;
          }
        }
      });
      
      // La raíz ("/") no siempre aparece en la lista, la agregamos manualmente
      // El ID de la raíz se puede obtener del campo orgUnitId del customer
      if (!Object.values(map).includes("/")) {
        Logger.log("[OU MAP] La OU raíz '/' no fue devuelta explícitamente por la API.");
      }
      
      Logger.log(`[OU MAP] Diccionario construido con ${Object.keys(map).length} entradas.`);
    } catch (e) {
      Logger.log(`[ERROR OU MAP] Fallo al extraer OUs: ${e.message}. El motor CEL no podrá resolver OU IDs.`);
    }
    return map;
  }

  /**
   * Almacena el diccionario OU en caché.
   * @param {Object} ouMap - Mapa { ouId: ouPath }
   */
  _saveOuMap(ouMap) {
    try {
      const json = JSON.stringify(ouMap);
      this.cache.put(this.OU_MAP_KEY, json, 1500); // 25 mins, igual que el censo
    } catch (e) {
      Logger.log(`[ERROR OU MAP] No se pudo guardar el mapa OU en caché: ${e.message}`);
    }
  }
}