import axios from "axios";
import { useState, useEffect } from "react";
import { Text, View } from "react-native";
import { useRouter } from 'expo-router';
import { Button } from 'react-native';

export default function Index() {
  const [data, setData] = useState<any>(null);
  const router = useRouter();

  useEffect(() => {
    axios.get("http://localhost:3000")
      .then(response => {
        setData(response.data);
      })
      .catch(error => {
        console.error("Error fetching data:", error);
      });
  }, []);

  return (
    <View
      style={{
        flex: 1,
        justifyContent: "center",
        alignItems: "center",
      }}
    >
      <Text> TODO index Screen  </Text>
      {data ? (
        <Text>{JSON.stringify(data, null, 2)}</Text>
      ) : (
        <Text>Loading...</Text>
      )}
      <Button
        title="Go to index"
        onPress={() => router.push('/')}
      />
    </View>
  );
}