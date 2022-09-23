package org.acme;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;

import javax.enterprise.context.ApplicationScoped;

import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

import org.jboss.logging.Logger;

import io.minio.BucketExistsArgs;
import io.minio.GetPresignedObjectUrlArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.ObjectWriteResponse;
import io.minio.UploadObjectArgs;
import io.minio.credentials.ClientGrantsProvider;
import io.minio.credentials.Jwt;
import io.minio.credentials.Provider;
import io.minio.errors.ErrorResponseException;
import io.minio.errors.InsufficientDataException;
import io.minio.errors.InternalException;
import io.minio.errors.InvalidResponseException;
import io.minio.errors.MinioException;
import io.minio.errors.ServerException;
import io.minio.errors.XmlParserException;
import io.minio.http.Method;
import io.minio.messages.Bucket;
import io.minio.messages.Tags;
import io.minio.messages.Upload;




@Path("/minio")
@ApplicationScoped
public class LifecyclResource {

    private static final String NA = "NA";
    private static Logger log = Logger.getLogger(LifecyclResource.class);

    @ConfigProperty(name = "org.acme.minIOendpointUrl")
    protected String minIOendpointUrl;

    @ConfigProperty(name = "org.acme.minIObucketName")
    protected String minIOBucketName;

    @ConfigProperty(name = "org.acme.minIOobjectPath")
    protected String minIOobjectPath;

    @ConfigProperty(name = "org.acme.minIOobjectTags")
    protected String minIOobjectTags;

    @ConfigProperty(name = "org.acme.printMinIOresponseHeaders", defaultValue="False")
    protected boolean printResponseHeaders;

    @ConfigProperty(name = "org.acme.minIOaccessKey", defaultValue = NA)
    protected String minIOaccessKey;

    @ConfigProperty(name = "org.acme.minIOsecretKey", defaultValue = NA)
    protected String minIOsecretKey;

    @ConfigProperty(name = "org.acme.oauth.idpEndpoint", defaultValue = NA)
    protected String oauthIDPendpoint;

    @ConfigProperty(name = "org.acme.oauth.clientId", defaultValue = NA)
    protected String oauthIDclientId;

    @ConfigProperty(name = "org.acme.oauth.clientSecret", defaultValue = NA)
    protected String oauthIDclientSecret;

    // MinioClient is thread safe :  https://github.com/minio/minio-java/issues/975
    private MinioClient mClient;

    private Random random = new Random();

    @PUT
    @Path("/lifecycle")
    @Produces(MediaType.TEXT_PLAIN)
    public Response bucketLifecycle() throws InvalidKeyException, NoSuchAlgorithmException, IllegalArgumentException, IOException {

        try{
            if(mClient == null)
              getMinIOclient();
              
            String preSignedUrl = executeLifecycle();
            
            String responseBody = "\nbucketLifecycle():  completed with preSignedUrl = "+preSignedUrl+"\n";
            return Response.ok(responseBody).build();
        }catch(MinioException x){
            x.printStackTrace();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("MinioException when invoking bucket lifecycle").build();
        }catch(Throwable x) {
            x.printStackTrace();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Throwable thrown when invoking bucket lifecycle").build();
        }
    }

    private void getMinIOclient()  {
        if(!minIOaccessKey.equals(NA)){
            log.infov("minio endpoint URL = {0} ; minio AccessKey = {1}", minIOendpointUrl, minIOaccessKey);
            mClient =
              MinioClient.builder()
                  .endpoint(minIOendpointUrl)
                  .credentials(minIOaccessKey, minIOsecretKey)
                  .build();
        }else if(!oauthIDPendpoint.equals(NA)) {
            log.infov("Endpoints:  \n\tminio URL = {0} \n\tOAuth2 IDP endpoint = {1}", minIOendpointUrl, oauthIDPendpoint);

            
                Provider provider = new ClientGrantsProvider(
                    () -> getJwt(oauthIDclientId, oauthIDclientSecret, oauthIDPendpoint), minIOendpointUrl, null, null, null
                );
        
                mClient = MinioClient.builder()
                    .endpoint(minIOendpointUrl)
                    .credentialsProvider(provider)
                    .build();

        } else {
            throw new RuntimeException("Must specify values for either a Minio service account or OAuth2 client credentials");
        }
        
        /*
        List<Bucket> buckets = mClient.listBuckets();
        log.infov("# of buckets found = {0}", buckets.size());
        for(Bucket bucket : buckets){
            log.infov("bucket name = {0}", bucket.name());
        }
        */
    }

    private Jwt getJwt(String clientId, String clientSecret, String idpEndpoint)  {
        Objects.requireNonNull(clientId, "Client id must not be null");
        Objects.requireNonNull(clientSecret, "ClientSecret must not be null");

        RequestBody requestBody =
            new FormBody.Builder()
            .add("client_id", clientId)
            .add("client_secret", clientSecret)
            .add("grant_type", "client_credentials")
            .build();

        Request request = new Request.Builder().url(idpEndpoint).post(requestBody).build();

        OkHttpClient client = new OkHttpClient();

        okhttp3.Response httpResponse = null;
        try {
            httpResponse = client.newCall(request).execute();
            ObjectMapper mapper = new ObjectMapper();
            mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            mapper.setVisibility(
            VisibilityChecker.Std.defaultInstance().withFieldVisibility(JsonAutoDetect.Visibility.ANY));
            return mapper.readValue(httpResponse.body().charStream(), Jwt.class);
        } catch (IOException e) {
            String errorMessage = "no http response";
            try {
                if(httpResponse != null)
                  errorMessage = httpResponse.body().string();
            }catch(Exception x){ }
            log.errorv("getJwt() http response from IDP = \n {0}", errorMessage);
            throw new ProviderException(e);
        }
    }

    //Returns pre-signed URL of bucket
    private String executeLifecycle() throws InvalidKeyException, ErrorResponseException, InsufficientDataException, InternalException, InvalidResponseException, NoSuchAlgorithmException, ServerException, XmlParserException, IllegalArgumentException, IOException {
        
        boolean bucketExists = mClient.bucketExists(BucketExistsArgs.builder().bucket(minIOBucketName).build());
        if(!bucketExists) {
            log.infov("About to make new bucket: {0}", minIOBucketName);
            mClient.makeBucket(MakeBucketArgs.builder().bucket(minIOBucketName).build());
        }

        Map<String, String> tags = new HashMap<String, String>();
        String[] tagsArray = minIOobjectTags.split(",");
        for(String pairs : tagsArray){
            String[] pair = pairs.split(":");
            tags.put(pair[0], pair[1]);
        }

        String objectName = "io.acme.object_"+random.nextInt(10000);
        log.infov("uploading object to {0} with following # of tags: {1}", minIOBucketName, tags.size());
        ObjectWriteResponse owResponse = mClient.uploadObject(UploadObjectArgs.builder().bucket(minIOBucketName).object(objectName).filename(minIOobjectPath).tags(tags).build());

        if(printResponseHeaders){
            Set<String> hNames = owResponse.headers().names();
            for(String key : hNames){
                log.infov("return header = {0} , {1}", key, owResponse.headers().get(key));
            }
        }

        String preSignedUrl = mClient.getPresignedObjectUrl(
            GetPresignedObjectUrlArgs.builder()
                .method(Method.GET)
                .bucket(minIOBucketName)
                .object(objectName)
                .expiry(60 * 60 * 24) // 1 day
                .build());
        
        return preSignedUrl;
    }
}
