package emu.lunarcore.server.http;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import emu.lunarcore.LunarCore;
import emu.lunarcore.LunarCore.ServerType;
import emu.lunarcore.config.ConfigData.HttpServerConfig;
import emu.lunarcore.config.ConfigManager;
import emu.lunarcore.proto.DispatchRegionDataOuterClass.DispatchRegionData;
import emu.lunarcore.server.game.RegionInfo;
import emu.lunarcore.server.http.handlers.*;
import emu.lunarcore.server.http.objects.HttpJsonResponse;
import emu.lunarcore.server.http.remote.*;
import emu.lunarcore.util.Utils;
import emu.lunarcore.server.game.GameSession;
import io.javalin.Javalin;
import io.javalin.http.ContentType;
import io.javalin.http.Context;
import it.unimi.dsi.fastutil.objects.Object2ObjectMap;
import it.unimi.dsi.fastutil.objects.Object2ObjectOpenHashMap;

//Datastore 

import com.mongodb.MongoClientSettings;
import com.mongodb.MongoException;
import com.mongodb.client.*;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import org.bson.Document;
import io.javalin.http.Handler;
import org.bson.conversions.Bson;
import static com.mongodb.client.model.Filters.*;

import java.util.Base64;

public class HttpServer {
    private final Javalin app;
    private final ServerType type;

    private List<String> modes;
    private boolean started;

    private MongoClient mongoClient;
    private MongoDatabase database;

    private long nextRegionUpdate;
    private Object2ObjectMap<String, RegionInfo> regions;
    private String regionList;

    public HttpServer(ServerType type) {
        this.type = type;
        this.app = Javalin.create(config -> {
            config.staticFiles.add("/public"); // This should point to `src/main/resources/public`
        });
        this.modes = new LinkedList<>();
        this.regions = new Object2ObjectOpenHashMap<>();

        try {
            mongoClient = MongoClients.create(
                    "mongodb+srv://biub7596:9Hu7JLu4hodemxnY@hsrdatabase.rbgx1.mongodb.net/?retryWrites=true&w=majority&appName=hsrdatabase");

            // Check for `moderatorData` database
            MongoIterable<String> databases = mongoClient.listDatabaseNames();
            if (!containsDatabase(databases, "moderatorData")) {
                mongoClient.getDatabase("moderatorData"); // Create the database if it doesn't exist
            }
            database = mongoClient.getDatabase("moderatorData");

            // Check for `accounts` collection and create it with necessary fields if not
            // exists
            MongoIterable<String> collections = database.listCollectionNames();
            if (!containsCollection(collections, "accounts")) {
                database.createCollection("accounts");
                MongoCollection<Document> collection = database.getCollection("accounts");
                collection.createIndex(Indexes.ascending("username"), new IndexOptions().unique(true));
            }
        } catch (MongoException e) {
            e.printStackTrace();
        }

        this.addRoutes();
    }

    private boolean containsDatabase(MongoIterable<String> databases, String databaseName) {
        for (String name : databases) {
            if (name.equals(databaseName))
                return true;
        }
        return false;
    }

    private boolean containsCollection(MongoIterable<String> collections, String collectionName) {
        for (String name : collections) {
            if (name.equals(collectionName))
                return true;
        }
        return false;
    }

    public Javalin getApp() {
        return this.app;
    }

    public ServerType getType() {
        return type;
    }

    public HttpServerConfig getServerConfig() {
        return ConfigManager.getConfig().getHttpServer();
    }

    public class LoginResponse {
        private String status;
        private String token;

        public LoginResponse(String status, String token) {
            this.status = status;
            this.token = token;
        }

        // Getters (if necessary)
        public String getStatus() {
            return status;
        }

        public String getToken() {
            return token;
        }

        // Setters (if necessary)
        public void setStatus(String status) {
            this.status = status;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }

    public class TokenCheckResponse {
        private String status;
        private String token;

        // Constructor
        public TokenCheckResponse(String status, String token) {
            this.status = status;
            this.token = token;
        }

        // Getters and setters
        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }

    private final Handler loginHandler = ctx -> {
        String username = ctx.formParam("username");
        String password = ctx.formParam("password");

        if (username == null || password == null) {
            ctx.status(400).result("Missing parameters");
            return;
        }

        LunarCore.getLogger().info("Received login attempt - Username: {}, Password: {}", username, password);

        MongoCollection<Document> collection = database.getCollection("accounts");

        // Query to find the user by username and password
        Bson filter = and(eq("username", username), eq("password", password));
        Document account = collection.find(filter).first();

        if (account != null) {
            String combined = username + ":" + password;
            String encodedToken = Base64.getEncoder().encodeToString(combined.getBytes());
            LunarCore.getLogger().info("Login successful for user: {}", username); // Log successful login
            // Return a successful response as JSON
            ctx.status(200).json(new LoginResponse("Valid", encodedToken));
        } else {
            LunarCore.getLogger().info("Invalid login attempt for user: {}", username); // Log invalid login
            // Return an invalid response as JSON
            ctx.status(401).json(new LoginResponse("Invalid", null));
        }
    };

    private final Handler checktokenvalid = ctx -> {
        // Retrieve token from the JSON body
        String token = ctx.bodyAsClass(Map.class).get("token").toString();

        if (token == null) {
            ctx.status(400).result("Missing token");
            LunarCore.getLogger().info("Client missing token"); 
            return; 
        }   

        try {
            // Decode the Base64 token to get username:password
            String decodedToken = new String(Base64.getDecoder().decode(token));
            String[] credentials = decodedToken.split(":");

            if (credentials.length != 2) {
                ctx.status(400).result("Invalid token format");
                return;
            }

            String username = credentials[0];
            String password = credentials[1];

            // Log the token check attempt
            LunarCore.getLogger().info("Received token check - Username: {}", username);

            // Query the `accounts` collection to find a match
            MongoCollection<Document> collection = database.getCollection("accounts");
            Document account = collection.find(and(eq("username", username), eq("password", password))).first();

            if (account != null) {
                LunarCore.getLogger().info("Token valid for user: {}", username);
                // Return valid response using TokenCheckResponse
                TokenCheckResponse response = new TokenCheckResponse("Valid", token);
                ctx.status(200).json(response);
            } else {
                LunarCore.getLogger().info("Invalid token for user: {}", username);
                // Return invalid response (401 Unauthorized)
                ctx.status(401).json(new LoginResponse("Invalid", null));
            }

        } catch (Exception e) {
            LunarCore.getLogger().error("Error decoding token or checking credentials", e);
            ctx.status(500).result("Internal server error");
        }
    };


    private HttpConnectionFactory getHttpFactory() {
        HttpConfiguration httpsConfig = new HttpConfiguration();
        SecureRequestCustomizer src = new SecureRequestCustomizer();
        src.setSniHostCheck(false);
        httpsConfig.addCustomizer(src);
        return new HttpConnectionFactory(httpsConfig);
    }

    private SslContextFactory.Server getSSLContextFactory() {
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath(ConfigManager.getConfig().getKeystore().getPath());
        sslContextFactory.setKeyStorePassword(ConfigManager.getConfig().getKeystore().getPassword());
        sslContextFactory.setSniRequired(false);
        sslContextFactory.setRenegotiationAllowed(false);
        return sslContextFactory;
    }

    public void forceRegionListRefresh() {
        this.nextRegionUpdate = 0;
    }

    public String getRegionList() {
        synchronized (this.regions) {
            // Check if region list needs to be cached
            if (System.currentTimeMillis() > this.nextRegionUpdate || this.regionList == null) {
                // Clear regions first
                this.regions.clear();

                // Pull region infos from database
                LunarCore.getAccountDatabase().getObjects(RegionInfo.class)
                        .forEach(region -> {
                            this.regions.put(region.getId(), region);
                        });

                // Serialize to proto
                DispatchRegionData regionData = DispatchRegionData.newInstance();
                regions.values().stream().map(RegionInfo::toProto).forEach(regionData::addRegionList);

                // Set region list cache
                this.regionList = Utils.base64Encode(regionData.toByteArray());
                this.nextRegionUpdate = System.currentTimeMillis() + getServerConfig().regionListRefresh;
            }
        }

        return regionList;
    }

    public void start() {
        if (this.started)
            return;
        this.started = true;
        WebHandler.initializeStartInfo();
        // Http server
        if (getServerConfig().isUseSSL()) {
            ServerConnector sslConnector = new ServerConnector(getApp().jettyServer().server(), getSSLContextFactory(),
                    getHttpFactory());
            sslConnector.setHost(getServerConfig().getBindAddress());
            sslConnector.setPort(getServerConfig().getBindPort());
            getApp().jettyServer().server().addConnector(sslConnector);

            getApp().start();
        } else {
            getApp().start(getServerConfig().getBindAddress(), getServerConfig().getBindPort());
        }

        // Done
        LunarCore.getLogger().info("Http Server running as: " + this.modes.stream().collect(Collectors.joining(", ")));
        LunarCore.getLogger().info("Http Server started on " + getServerConfig().getBindPort());
    }


    private final Handler getplayer = ctx -> {
        ctx.json(Map.of("playerCount", GameSession.getActiveClientCount())); // Sends player count as JSON response
    };
    private final Handler cpuHandler = WebHandler.cpuHandler;
    private final Handler getinit =  WebHandler.cpuHistoryHandler;
    private void addRoutes() {
        // Add routes based on what type of server this is
        if (this.getType().runDispatch()) {
            this.addDispatchRoutes();
            this.addLogServerRoutes();
        }
        if (this.getType().runGame()) {
            this.addGateServerRoutes();
            this.addRemoteRoutes();
        }
        getApp().get("/", ctx -> {
            String htmlContent = Utils.readFile("public/index.html"); // Load index.html from `public` directory
            ctx.contentType(ContentType.TEXT_HTML).result(htmlContent);
        });
        getApp().get("/login", ctx -> {
            String htmlContent = Utils.readFile("public/index.html"); // Serve index.html for all routes
            ctx.contentType(ContentType.TEXT_HTML).result(htmlContent);
        });
        getApp().get("/dashboard", ctx -> {
            String htmlContent = Utils.readFile("public/index.html"); // Serve index.html for all routes
            ctx.contentType(ContentType.TEXT_HTML).result(htmlContent);
        });
        app.get("/request/getcpuusage", cpuHandler);
        app.post("/request/login", loginHandler);
        app.post("/request/tokencheck", checktokenvalid);
        app.get("/request/getplayer", getplayer);
        app.get("/request/init", getinit);
        getApp().error(404, this::notFoundHandler);
    }

    private void addDispatchRoutes() {
        // Get region info
        getApp().get("/query_dispatch", new QueryDispatchHandler(this));

        // Captcha -> api-account-os.hoyoverse.com
        getApp().post("/account/risky/api/check", new HttpJsonResponse(
                "{\"retcode\":0,\"message\":\"OK\",\"data\":{\"id\":\"none\",\"action\":\"ACTION_NONE\",\"geetest\":null}}"));

        // === AUTHENTICATION === hkrpg-sdk-os-static.hoyoverse.com

        // Username & Password login (from client). Returns a session key to the client.
        getApp().post("/hkrpg_global/mdk/shield/api/login", new UsernameLoginHandler());
        // Cached session key verify (from registry). Returns a session key to the
        // client.
        getApp().post("/hkrpg_global/mdk/shield/api/verify", new TokenLoginHandler());

        // Exchange session key for login token (combo token)
        getApp().post("/hkrpg_global/combo/granter/login/v2/login", new ComboTokenGranterHandler());

        // Config
        getApp().get("/hkrpg_global/combo/granter/api/getConfig", new HttpJsonResponse(
                "{\"retcode\":0,\"message\":\"OK\",\"data\":{\"protocol\":true,\"qr_enabled\":false,\"log_level\":\"INFO\",\"announce_url\":\"\",\"push_alias_type\":0,\"disable_ysdk_guard\":true,\"enable_announce_pic_popup\":false,\"app_name\":\"崩�??RPG\",\"qr_enabled_apps\":{\"bbs\":false,\"cloud\":false},\"qr_app_icons\":{\"app\":\"\",\"bbs\":\"\",\"cloud\":\"\"},\"qr_cloud_display_name\":\"\",\"enable_user_center\":true,\"functional_switch_configs\":{}}}"));
        getApp().get("/hkrpg_global/mdk/shield/api/loadConfig", new HttpJsonResponse(
                "{\"retcode\":0,\"message\":\"OK\",\"data\":{\"id\":24,\"game_key\":\"hkrpg_global\",\"client\":\"PC\",\"identity\":\"I_IDENTITY\",\"guest\":false,\"ignore_versions\":\"\",\"scene\":\"S_NORMAL\",\"name\":\"崩�??RPG\",\"disable_regist\":false,\"enable_email_captcha\":false,\"thirdparty\":[\"fb\",\"tw\",\"gl\",\"ap\"],\"disable_mmt\":false,\"server_guest\":false,\"thirdparty_ignore\":{},\"enable_ps_bind_account\":false,\"thirdparty_login_configs\":{\"tw\":{\"token_type\":\"TK_GAME_TOKEN\",\"game_token_expires_in\":2592000},\"ap\":{\"token_type\":\"TK_GAME_TOKEN\",\"game_token_expires_in\":604800},\"fb\":{\"token_type\":\"TK_GAME_TOKEN\",\"game_token_expires_in\":2592000},\"gl\":{\"token_type\":\"TK_GAME_TOKEN\",\"game_token_expires_in\":604800}},\"initialize_firebase\":false,\"bbs_auth_login\":false,\"bbs_auth_login_ignore\":[],\"fetch_instance_id\":false,\"enable_flash_login\":false}}"));

        // === EXTRA ===

        // hkrpg-sdk-os.hoyoverse.com
        getApp().post("/hkrpg_global/combo/granter/api/compareProtocolVersion", new HttpJsonResponse(
                "{\"retcode\":0,\"message\":\"OK\",\"data\":{\"modified\":false,\"protocol\":null}}"));
        getApp().get("/hkrpg_global/mdk/agreement/api/getAgreementInfos",
                new HttpJsonResponse("{\"retcode\":0,\"message\":\"OK\",\"data\":{\"marketing_agreements\":[]}}"));

        // sdk-os-static.hoyoverse.com
        getApp().get("/combo/box/api/config/sdk/combo", new HttpJsonResponse(
                "{\"retcode\":0,\"message\":\"OK\",\"data\":{\"vals\":{\"kibana_pc_config\":\"{ \\\"enable\\\": 0, \\\"level\\\": \\\"Info\\\",\\\"modules\\\": [\\\"download\\\"] }\\n\",\"network_report_config\":\"{ \\\"enable\\\": 0, \\\"status_codes\\\": [206], \\\"url_paths\\\": [\\\"dataUpload\\\", \\\"red_dot\\\"] }\\n\",\"list_price_tierv2_enable\":\"false\\n\",\"pay_payco_centered_host\":\"bill.payco.com\",\"telemetry_config\":\"{\\n \\\"dataupload_enable\\\": 0,\\n}\",\"enable_web_dpi\":\"true\"}}}"));
        getApp().get("/combo/box/api/config/sw/precache", new HttpJsonResponse(
                "{\"retcode\":0,\"message\":\"OK\",\"data\":{\"vals\":{\"url\":\"\",\"enable\":\"false\"}}}"));

        // sg-public-data-api.hoyoverse.com
        getApp().get("/device-fp/api/getFp", new FingerprintHandler());
        getApp().get("/device-fp/api/getExtList", new HttpJsonResponse(
                "{\"retcode\":0,\"message\":\"OK\",\"data\":{\"code\":200,\"msg\":\"ok\",\"ext_list\":[],\"pkg_list\":[],\"pkg_str\":\"/vK5WTh5SS3SAj8Zm0qPWg==\"}}"));

        // abtest-api-data-sg.hoyoverse.com
        getApp().post("/data_abtest_api/config/experiment/list", new HttpJsonResponse(
                "{\"retcode\":0,\"success\":true,\"message\":\"\",\"data\":[{\"code\":1000,\"type\":2,\"config_id\":\"14\",\"period_id\":\"6125_197\",\"version\":\"1\",\"configs\":{\"cardType\":\"direct\"}}]}"));

        // Add mode
        this.modes.add("DISPATCH");
    }

    private void addLogServerRoutes() {
        // hkrpg-log-upload-os.hoyoverse.com
        getApp().post("/sdk/dataUpload", new HttpJsonResponse("{\"code\":0}"));

        // log-upload-os.hoyoverse.com
        getApp().post("/crashdump/dataUpload", new HttpJsonResponse("{\"code\":0}"));
        getApp().post("/apm/dataUpload", new HttpJsonResponse("{\"code\":0}"));

        // minor-api-os.hoyoverse.com
        getApp().post("/common/h5log/log/batch",
                new HttpJsonResponse("{\"retcode\":0,\"message\":\"success\",\"data\":null}"));
    }

    private void addGateServerRoutes() {
        // Gateway info
        getApp().get("/query_gateway", new QueryGatewayHandler());

        // Add mode
        this.modes.add("GATESERVER");
    }

    private void addRemoteRoutes() {
        // Remote handler
        getApp().post("/api/papply", new ApplyHandler());
        getApp().post("/api/pverify", new VerifyHandler());
        getApp().post("/api/premote", new PlayerRemoteHandler());
        getApp().post("/api/cremote", new ConsoleRemoteHandler());
    }

    private void notFoundHandler(Context ctx) {
        ctx.status(404);
        ctx.contentType(ContentType.TEXT_PLAIN);
        ctx.result("not found");
    }
}