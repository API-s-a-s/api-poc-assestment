/**
 * Estrategia de Auditoría para la Configuración de inicio de sesión del navegador Chrome.
 * Evalúa si la organización restringe o permite el inicio de sesión de perfiles gestionados.
 * * ID Evaluado: ID-161
 * Configuración Evaluada: Configuración de inicio de sesión del navegador
 * Filtro de Esquema / Búsqueda: chrome.users.BrowserSignin
 * Variable de Configuración Real API: browserSignin (formato camelCase corregido)
 */
class ChromeBrowserSigninStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-161",
        valueKey: "valorPrincipal",
        noteKey: "comentario161",
        riskKey: "riesgo161",
        scoreKey: "score161"
      }
    ];

    super("Chrome Browser Sign-in Settings Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.BrowserSignin' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución que contiene la autenticación.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-161 (INICIO DE SESIÓN EN CHROME) ==========");

    // 1. Obtener la cabecera de autenticación mediante DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-161] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-161 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Resolver dinámicamente el ID de la OU raíz (Utilizando el fallback inteligente)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-161] ID de OU raíz resuelto desde parentOrgUnitId: ${rootOuId}`);
      }
    } catch (e) {
      Logger.log(`[ID-161 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}. Se intentará usar customerId.`);
    }

    // Fallback: Si no hay OUs hijas, la API suele aceptar el customerId como contenedor de la raíz
    const targetResource = rootOuId ? `orgunits/${rootOuId}` : `orgunits/${this.customerId}`;
    Logger.log(`[ID-161] Target Resource definitivo para la API: ${targetResource}`);

    let browserSigninValue = null;
    let anyFound = false;

    // 3. Consultar la política efectiva a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.BrowserSignin",
      pageSize: 10
    };

    const options = {
      method: "post",
      headers: {
        ...dwdHeader,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };

    Logger.log("[ID-161] Enviando petición POST a policies:resolve para 'chrome.users.BrowserSignin'...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-161 - DETALLE API] Código de Respuesta HTTP: ${code}`);
      Logger.log(`[ID-161 - DETALLE API] Cuerpo de Respuesta Raw: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy, index) => {
            Logger.log(`[ID-161 - PARSEO] Procesando política resuelta [${index + 1}]`);
            // Extracción de la variable corregida a camelCase: browserSignin
            const val = policy.value && policy.value.value;
            if (val && val.browserSignin !== undefined) {
              browserSigninValue = val.browserSignin;
              Logger.log(`[ID-161 - PARSEO] Encontrada variable 'browserSignin'. Valor: ${browserSigninValue}`);
            }
          });
        } else {
          Logger.log("[ID-161 - INFO] La API respondió exitosamente pero no hay políticas explícitas configuradas para este esquema (Hereda por defecto).");
        }
      } else {
        Logger.log(`[ID-161 - ERROR] La API de resolución devolvió el código HTTP no exitoso: ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-161 - ERROR] Excepción de red detectada al invocar el endpoint: ${e.message}`);
    }

    // 4. Criterio de Auditoría, Asignación de Riesgo y Construcción de la Respuesta
    // Valores estándar conocidos de la API: 
    // - 0 o "BROWSER_SIGNIN_MODE_ENUM_DISABLED": Deshabilitado
    // - 1 o "BROWSER_SIGNIN_MODE_ENUM_ENABLED": Habilitado (El usuario decide)
    // - 2 o "BROWSER_SIGNIN_MODE_ENUM_FORCED": Forzado (Obliga a loguearse para usar el navegador)
    
    let riesgo161, comentario161, valorPrincipal;

    if (!anyFound || browserSigninValue === null) {
      // Estado no configurado de forma explícita en la raíz
      riesgo161 = "Medio";
      valorPrincipal = "No Configurado (Por Defecto)";
      comentario161 = "La política de inicio de sesión no está definida explícitamente en la raíz. Chrome aplica el comportamiento por defecto permitiendo que los usuarios decidan si inician sesión o no, lo que dificulta la aplicación de directivas persistentes de seguridad a nivel de perfil corporativo.";
    } else {
      const valorStr = browserSigninValue.toString();
      
      if (valorStr.includes("FORCED") || valorStr === "2") {
        riesgo161 = "Bajo";
        valorPrincipal = "Forzado (Seguro)";
        comentario161 = `El inicio de sesión en el navegador está configurado como FORZADO (${valorStr}). Esto garantiza que los usuarios deben autenticarse de manera obligatoria con su cuenta institucional para utilizar Chrome, permitiendo la bajada estricta y auditoría de políticas corporativas.`;
      } else if (valorStr.includes("DISABLED") || valorStr === "0") {
        riesgo161 = "Alto";
        valorPrincipal = "Deshabilitado";
        comentario161 = `El inicio de sesión de perfiles está explícitamente DESHABILITADO (${valorStr}). Los empleados no pueden sincronizar sus cuentas empresariales ni recibir extensiones o políticas de datos críticas para la protección de la organización.`;
      } else {
        // En este caso es "ENABLED" / 1
        riesgo161 = "Medio";
        valorPrincipal = "Habilitado Opcional";
        comentario161 = `El inicio de sesión está configurado como HABILITADO OPCIONAL (${valorStr}). El usuario final decide de forma voluntaria si vincula su cuenta corporativa o utiliza un perfil de Chrome anónimo/personal para navegar por datos de la empresa, lo que debilita el perímetro de control.`;
      }
    }

    Logger.log(`[ID-161] Diagnóstico completado. Valor detectado: ${browserSigninValue} | Riesgo: ${riesgo161}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-161 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario161: comentario161,
      riesgo161: riesgo161,
      score161: this.calcularScoreDeRiesgo(riesgo161)
    };
  }

  /**
   * Mapea el string de riesgo a la escala numérica estándar.
   */
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  /**
   * Respuesta de contingencia en caso de excepciones severas.
   */
  _buildErrorResponse(msg) {
    Logger.log(`[ID-161] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario161: `Ocurrió un error inesperado al procesar la API para esta directiva: ${msg}`,
      riesgo161: "Medio",
      score161: 2
    };
  }
}