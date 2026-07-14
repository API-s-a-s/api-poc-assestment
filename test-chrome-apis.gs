/**
 * Suite de pruebas para el Chrome Policy API.
 * Permite listar esquemas disponibles (schemas) y resolver las políticas efectivas (resolve)
 * a nivel de cada Unidad Organizativa (OU) utilizando DWD con la cuenta de servicio.
 */
class ChromeApiTester {
  constructor() {
    this.auth = new AuthService();
    this.customerId = this.auth.getCustomerId(); // ej: "my_customer"
    this.adminEmail = this.auth.getCurrentUserEmail();
  }

  /**
   * Ejecuta la suite completa de pruebas para las APIs de Chrome.
   */
  runAllTests() {
    Logger.log("==========================================================================");
    Logger.log("🧪 INICIANDO DIAGNÓSTICO DE CHROME POLICY API");
    Logger.log(`Cliente: ${this.customerId} | Administrador: ${this.adminEmail}`);
    Logger.log("==========================================================================");

    // 1. Obtener la cabecera de autenticación mediante DWD
    let dwdHeader = null;
    try {
      dwdHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[AUTH] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[AUTH - ERROR CRÍTICO] No se pudo obtener el token DWD: ${e.message}`);
      Logger.log("Asegúrese de que el scope 'https://www.googleapis.com/auth/chrome.management.policy.readonly' esté autorizado en el DWD de la cuenta de servicio en la consola de Google Admin.");
      return;
    }

    // 2. Listar esquemas disponibles (Discovery / Metadata)
    this.testListChromeSchemas(dwdHeader);

    // 3. Obtener Unidades Organizativas y resolver las políticas aplicadas
    this.testResolveChromePoliciesForOUs(dwdHeader);

    Logger.log("==========================================================================");
    Logger.log("🏁 DIAGNÓSTICO DE CHROME POLICY API COMPLETADO");
    Logger.log("==========================================================================");
  }

  /**
   * Consulta el registro de esquemas de políticas de Chrome (policySchemas)
   * para validar qué políticas e identificadores exactos están disponibles.
   */
  testListChromeSchemas(authHeader) {
    Logger.log("\n--- [1] LISTANDO REGISTRO DE ESQUEMAS (SCHEMAS) EN EL INQUILINO ---");

    const namespaces = ["chrome.users.*", "chrome.devices.*"];
    
    namespaces.forEach(ns => {
      const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policySchemas?filter=${encodeURIComponent("name=" + ns)}&pageSize=1000`;
      
      Logger.log(`[TEST] Buscando esquemas bajo el filtro: ${ns}`);
      
      this.executeApiCall("GET", url, authHeader, null, (json) => {
        const schemas = json.policySchemas || [];
        Logger.log(`[SUCCESS] Se encontraron ${schemas.length} esquemas bajo el namespace ${ns}.`);
        
        if (schemas.length > 0) {
          Logger.log(`[INFO] Listando las primeras 15 variables de configuración encontradas en '${ns}':`);
          schemas.slice(0, 15).forEach((schema, idx) => {
            const schemaId = schema.name.split("/").pop(); // Extraer el ID del esquema del final del path completo
            Logger.log(`  ${idx + 1}. Esquema: ${schemaId}`);
            
            // Si el esquema tiene definición de campos (fieldDescriptions), listarlos
            if (schema.definition && schema.definition.messageType) {
              const fields = schema.definition.messageType.map(f => `${f.name} (${f.type})`).join(", ");
              Logger.log(`     Campos: [ ${fields} ]`);
            }
          });
        } else {
          Logger.log(`[WARN] No se devolvieron esquemas para el namespace ${ns}.`);
        }
      });
    });
  }

  /**
   * Resuelve y evalúa las políticas reales configuradas para cada una de las OUs
   * del dominio, utilizando el método policies:resolve.
   */
  testResolveChromePoliciesForOUs(authHeader) {
    Logger.log("\n--- [2] RESOLVIENDO POLÍTICAS DE CHROME POR UNIDAD ORGANIZATIVA (OU) ---");

    // A. Obtener todas las OUs disponibles usando AdminDirectory
    let orgUnits = [];
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      orgUnits = response.organizationUnits || [];
      Logger.log(`[INFO] Se obtuvieron ${orgUnits.length} Unidades Organizativas desde el Directorio.`);
    } catch (e) {
      Logger.log(`[WARN] Falló la obtención de OUs desde AdminDirectory: ${e.message}. Se usará la raíz '/' como fallback.`);
    }

    // Asegurarse de agregar la raíz si no está explícitamente en la lista
    if (!orgUnits.some(ou => ou.orgUnitPath === "/")) {
      orgUnits.unshift({
        orgUnitId: "", // La raíz puede dejarse vacía o resolverse por defecto
        orgUnitPath: "/",
        name: "Raíz"
      });
    }

    const filters = ["chrome.users.*", "chrome.devices.*"];

    // B. Iterar sobre las OUs y resolver políticas
    orgUnits.forEach(ou => {
      // Normalizar el ID de la OU
      // Si no hay ID de OU (ej: la raíz), usamos el customer ID de manera implícita o resolvemos sin el ID de OU
      const cleanOuId = ou.orgUnitId ? ou.orgUnitId.replace(/^id:/, "") : "";
      const targetResource = cleanOuId ? `orgunits/${cleanOuId}` : `orgunits/`; // Si está vacío, suele representar la raíz
      
      Logger.log(`\n-------------------------------------------------------------`);
      Logger.log(`🏢 Evaluando OU: '${ou.orgUnitPath}' (ID: ${cleanOuId || "Raíz / Default"})`);
      Logger.log(`-------------------------------------------------------------`);

      filters.forEach(filter => {
        const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
        
        const payload = {
          policyTargetKey: {
            targetResource: targetResource
          },
          policySchemaFilter: filter,
          pageSize: 100
        };

        Logger.log(`[TEST] Resolviendo políticas para filtro '${filter}'...`);

          this.executeApiCall("POST", url, authHeader, payload, (json) => {          
          // =========================================================
          // 💡 NUEVO: IMPRIMIR LA ESTRUCTURA COMPLETA DEL JSON CRUDO
          // =========================================================
          Logger.log(`\n⬇️⬇️ ESTRUCTURA COMPLETA DEL JSON PARA: ${filter} ⬇️⬇️`);
          Logger.log(JSON.stringify(json, null, 2));
          Logger.log(`⬆️⬆️ FIN DEL JSON ⬆️⬆️\n`);
          // =========================================================

          const resolvedPolicies = json.resolvedPolicies || [];
          Logger.log(`[SUCCESS] Encontradas ${resolvedPolicies.length} políticas configuradas/resueltas.`);

          if (resolvedPolicies.length > 0) {
            resolvedPolicies.forEach((item, idx) => {
              const schemaId = item.value ? item.value.policySchema : "Desconocido";
              const valueObj = item.value ? item.value.value : {};
              const sourceKey = item.sourceKey ? item.sourceKey.targetResource : "Inherited";
              
              Logger.log(`  🔍 [${idx + 1}] Esquema: ${schemaId}`);
              Logger.log(`     Origen: ${sourceKey}`);
              Logger.log(`     Valor: ${JSON.stringify(valueObj)}`);
            });
          }
        });
      });
    });
  }

  /**
   * Helper genérico para realizar llamadas HTTP seguras con control de errores y backoff.
   */
  executeApiCall(method, url, authHeader, payload = null, onSuccessCallback = null) {
    const options = {
      method: method.toLowerCase(),
      headers: {
        ...authHeader,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
      muteHttpExceptions: true
    };

    if (payload) {
      options.payload = JSON.stringify(payload);
    }

    let retries = 0;
    const maxRetries = 3;

    while (retries < maxRetries) {
      try {
        const response = UrlFetchApp.fetch(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();

        if (code === 200) {
          const json = JSON.parse(text);
          if (onSuccessCallback) {
            onSuccessCallback(json);
          }
          return;
        } else if (code === 429 || code >= 500) {
          retries++;
          const sleepTime = Math.pow(2, retries) * 1000 + Math.floor(Math.random() * 500);
          Logger.log(`[WARN] HTTP ${code} detectado. Reintentando en ${sleepTime}ms (Intento ${retries}/${maxRetries})...`);
          Utilities.sleep(sleepTime);
        } else {
          Logger.log(`[FAILED] Petición falló con código HTTP ${code}. Respuesta: ${text}`);
          return;
        }
      } catch (e) {
        Logger.log(`[ERROR EXCEPCIÓN] Error de red o parseo: ${e.message}`);
        return;
      }
    }

    Logger.log(`[FAILED] Se alcanzó el número máximo de reintentos (${maxRetries}) sin éxito.`);
  }
}

/**
 * Función global para ejecutar las pruebas desde el editor de Google Apps Script.
 */
function runChromeApiTests() {
  const tester = new ChromeApiTester();
  tester.runAllTests();
}
